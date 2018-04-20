#if SERVERSIDE
using System;
using System.Collections.Generic;
using System.Text;
using System.Net.Sockets;
using System.Net;
using System.Threading;
using System.Diagnostics;
using KCP.Common;

namespace KCP.Server
{


    public delegate void RecvDataHandler(ClientSession session, byte[] data, int offset, int size);

    /// <summary>
    /// 支持连接管理的KCPserver。
    /// 外部组件通过AddClientKey方法增加合法的客户端conv(index)和key信息。
    /// 客户端握手时，如果不存在握手请求中的conv（index）和key，握手将失败。
    /// </summary>
    public class KCPServer
    {
        private static readonly DateTime utc_time = new DateTime(1970, 1, 1);

        public static UInt32 iclock()
        {
            return (UInt32)(Convert.ToInt64(DateTime.UtcNow.Subtract(utc_time).TotalMilliseconds) & 0xffffffff);
        }
        private string m_host;
        private ushort m_port;
        private Socket m_UdpSocket;

        internal Stopwatch m_watch;
        private SwitchQueue<SocketAsyncEventArgs> mRecvQueue = new SwitchQueue<SocketAsyncEventArgs>(128);
        private int BUFFSIZE = 8 * 1024;
        private AutoResetEvent m_DataReceived = new AutoResetEvent(true);


        /// <summary>
        /// 收到数据事件
        /// 数据来自KCPServer.BytePool，调用完毕将立即回收。
        /// 如果有需要，请自行Copy。
        /// </summary>
        public event RecvDataHandler RecvData;

        /// <summary>
        /// 新的客户端连接事件
        /// </summary>
        public event RecvDataHandler NewClientSession;
        public INewClientSessionProcessor NewSessionProcessor { get; set; }

        internal void OnRecvData(ClientSession session, byte[] data, int offset, int size)
        {
            RecvData?.Invoke(session, data, offset, size);
        }

        public event Action<ClientSession> CloseClientSession;
        internal void OnCloseClientSession(ClientSession clientSession)
        {
            CloseClientSession?.Invoke(clientSession);
        }


        public ArrayPool<byte> BytePool;

        public KCPServer(string host, UInt16 port)
        {
            m_host = host;
            m_port = port;

            if (UdpLibConfig.UseBytePool)
            {
                BytePool = ArrayPool<byte>.Create(8 * 1024, 50);
            }
            else
            {
                BytePool = ArrayPool<byte>.System();
            }

            KCPLib.BufferAlloc = (size) =>
            {
                return BytePool.Rent(size);
            };
            KCPLib.BufferFree = (buf) =>
            {
                BytePool.Return(buf);
            };

        }
        public void StartReceive()
        {
            m_watch = Stopwatch.StartNew();
            m_UdpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            m_UdpSocket.Bind(new IPEndPoint(IPAddress.Parse(m_host), m_port));
            var e = PopSAE();
            m_UdpSocket.ReceiveFromAsync(e);
        }

        private void E_Completed(object sender, SocketAsyncEventArgs e)
        {
            if (e.LastOperation == SocketAsyncOperation.ReceiveFrom)
            {
#if DEV
                uint index = 0, key = 0;
                if(IsHandshake(e.Buffer, 0, e.BytesTransferred, out index, out key)) {
                    IRQLog.AppLog.Log(index.ToString() + ",收到数据");
                }
#endif
                mRecvQueue.Push(e); //唯一一个Push的地方
                m_DataReceived.Set(); //唯一一个Set的地方，在UpdateRepeatedly的第一行使用。
                m_UdpSocket.ReceiveFromAsync(PopSAE());
            }
            else if (e.LastOperation == SocketAsyncOperation.SendTo)
            {
                PushSAE(e); //对象失效，入库
            }
        }

        private Stack<SocketAsyncEventArgs> m_saePool = new Stack<SocketAsyncEventArgs>();
        /// <summary>
        /// 找到一个空闲的对象出库，如果没有空闲，则创建10个。
        /// </summary>
        private SocketAsyncEventArgs PopSAE()
        {
            lock (m_saePool)
            {
                if (m_saePool.Count == 0)
                {
                    for (int i = 0; i < 10; i++)
                    {
                        SocketAsyncEventArgs e = new SocketAsyncEventArgs();
                        e.RemoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
                        e.Completed += E_Completed;
                        e.SetBuffer(new byte[BUFFSIZE], 0, BUFFSIZE);
                        m_saePool.Push(e);
                    }
                }
                return m_saePool.Pop();
            }
        }
        private void PushSAE(SocketAsyncEventArgs e)
        {
            lock (m_saePool)
            {
                m_saePool.Push(e);
            }
        }

        public void UpdateRepeatedly()
        {
            m_DataReceived.WaitOne(1);
            ProcessDisposedQueue();
            ProcessRecvQueue();
            ProcessClientSession();
        }

        private void ProcessClientSession()
        {
            m_SessionLocker.EnterReadLock();
            foreach (var v in m_clients.Values)
            {
                v.Update();
            }
            m_SessionLocker.ExitReadLock();
        }

        private Queue<ClientSession> m_disposedQueue = new Queue<ClientSession>();
        internal void AddToDisposedQueue(ClientSession clientSession)
        {
            m_disposedQueue.Enqueue(clientSession);
        }
        /// <summary>
        /// 处理释放的客户端
        /// </summary>
        private void ProcessDisposedQueue()
        {
            while (m_disposedQueue.Count > 0)
            {
                var e = m_disposedQueue.Dequeue();
                RemoveClientSession(e);
                RmeoveClientKey(e.NetIndex);
                e.m_Kcp.Dispose();
                CloseClientSession?.Invoke(e);
            }
        }

        private bool IsHandshake(byte[] buffer, int offset, int size, out uint index, out uint key)
        {
            if (HandshakeUtility.IsHandshakeDataRight(buffer, offset, size, out index, out key))
            {
                return IsClientKeyCorrect(index, (int)key);
            }
            else
            {
                return false;
            }
        }

        private bool TryProcessHandShake(SocketAsyncEventArgs e, out uint index)
        {
            index = 0;
            uint key = 0;
            //使用纯udp进行握手，8字节0xFF+4字节conv+4字节key
            if (!IsHandshake(e.Buffer, e.Offset, e.BytesTransferred, out index, out key))
            {
                return false;
            }

            var c = GetSession(index);
            uint cc = 0;
            KCPLib.ikcp_decode32u(e.Buffer, e.Offset + 16, ref cc);
            if (c == null)
            {
                //新连接处理，如果返回false，则不予处理，可以用来进行非法连接的初步处理
                if (NewSessionProcessor != null && !NewSessionProcessor.OnNewSession(index, e.RemoteEndPoint))
                {
                    PushSAE(e);
                    return true;
                }

                c = AddSession(e.RemoteEndPoint, index);
                c.m_KCPServer = this;
                c.m_LastRecvTimestamp = m_watch.Elapsed;
                NewClientSession?.Invoke(c, e.Buffer, e.Offset, e.BytesTransferred);
#if DEV
                        IRQLog.AppLog.Log(index.ToString() + ",连接1," + cc.ToString());
#endif
            }
            else
            {
#if DEV
                        IRQLog.AppLog.Log(index.ToString() + ",连接2," + cc.ToString());
#endif
                c.EndPoint = e.RemoteEndPoint;
                //如果客户端关闭并且立刻重连，这时候是连不上的，因为KCP中原有的数据不能正确处理
                //c.ResetKCP();
                //GG: 待处理。
            }

            c.Status = ClientSessionStatus.Connected;
            //回发握手请求
            if (UdpLibConfig.ServerSendAsync)
            {
                m_UdpSocket.SendToAsync(e);
            }
            else
            {
#if DEBUG
                Stopwatch sw = Stopwatch.StartNew();
                m_UdpSocket.SendTo(e.Buffer, e.Offset, e.BytesTransferred, SocketFlags.None, e.RemoteEndPoint);
                Console.WriteLine((sw.ElapsedTicks * 1000f / Stopwatch.Frequency));
#else
                        m_UdpSocket.SendTo(e.Buffer, e.Offset, e.BytesTransferred, SocketFlags.None, e.RemoteEndPoint);

#endif
                PushSAE(e);
            }
#if DEV
                    IRQLog.AppLog.Log(index.ToString() + ",发送数据UDP");
#endif
            return true;
        }

        /// <summary>
        /// 仅仅在UpdateRepeatedly里面调用。
        /// 如果是握手信息，则创建Session，并返回握手应答；否则让ClientSession自己处理。
        /// </summary>
        private void ProcessRecvQueue()
        {
            mRecvQueue.Switch();
            while (!mRecvQueue.Empty())
            {
                var e = mRecvQueue.Pop();
                if (e.BytesTransferred == 0)
                { //说明客户端关闭了，GG：UDP不知道客户端关闭的事情吧？
                    PushSAE(e);
                    continue;
                }

                uint index;
                if (TryProcessHandShake(e, out index))
                    continue;

                try
                {
                    KCPLib.ikcp_decode32u(e.Buffer, e.Offset, ref index);
                    var clientSession = GetSession(index);
                    if (clientSession != null && clientSession.Status == ClientSessionStatus.Connected)
                    {
                        Debug.Assert(clientSession.EndPoint.ToString() == e.RemoteEndPoint.ToString());
                        //c.EndPoint = e.RemoteEndPoint;

                        clientSession.process_recv_queue(e);
                    }
                }
                finally
                {  //GG: 使用Disposeale将PushSAE放在一起。简化代码。
                    PushSAE(e);
                }
            }
        }

        /// <summary>
        /// 仅仅从ClientSession里面调用
        /// </summary>
        internal void Send(ClientSession session, byte[] data, int offset, int size)
        {
            //mUdpServer.SendToAsync
            // Stopwatch sw = Stopwatch.StartNew();
            if (UdpLibConfig.ServerSendAsync)
            {
                var e = PopSAE();
                e.RemoteEndPoint = session.EndPoint;
                Array.Copy(data, offset, e.Buffer, 0, size);
                e.SetBuffer(0, size);
                m_UdpSocket.SendToAsync(e);
            }
            else
            {
                m_UdpSocket.SendTo(data, offset, size, SocketFlags.None, session.EndPoint);
            }
#if DEV
            IRQLog.AppLog.Log(session.NetIndex.ToString() + ",发送数据KCP");
#endif
            // Console.WriteLine(((double)sw.ElapsedTicks / Stopwatch.Frequency) * 1000);
        }

        #region ClientSession
        //Dictionary<EndPoint, ClientSession> m_clients = new Dictionary<EndPoint, ClientSession>();
        Dictionary<uint, int> m_clientsKey = new Dictionary<uint, int>();
        Dictionary<uint, ClientSession> m_clients = new Dictionary<uint, ClientSession>();
        ReaderWriterLockSlim m_SessionLocker = new ReaderWriterLockSlim();
        ReaderWriterLockSlim m_KeyLocker = new ReaderWriterLockSlim();
        private object LOCK = new object();
        private ClientSession GetSession(uint index)
        {
            ClientSession ret;
            m_SessionLocker.EnterReadLock();
            m_clients.TryGetValue(index, out ret);
            m_SessionLocker.ExitReadLock();
            return ret;
        }

        private ClientSession AddSession(EndPoint remoteEndPoint, uint index)
        {
            m_SessionLocker.EnterWriteLock();
            var ret = new ClientSession(index);
            ret.EndPoint = remoteEndPoint;

            m_clients.Add(index, ret);
            m_SessionLocker.ExitWriteLock();
            return ret;
        }

        public void RemoveClientSession(ClientSession session)
        {
            m_SessionLocker.EnterWriteLock();
            m_clients.Remove(session.NetIndex);
            m_SessionLocker.ExitWriteLock();

        }
        /// <summary>
        /// 增加客户端 conv(index)和key        
        /// </summary>
        /// <param name="index"></param>
        /// <param name="key"></param>
        public void AddClientKey(uint index, int key)
        {
            m_KeyLocker.EnterWriteLock();
            if (m_clientsKey.ContainsKey(index))
            {
                m_clientsKey.Remove(index);
            }
            m_clientsKey.Add(index, key);
            m_KeyLocker.ExitWriteLock();
        }
        public void RmeoveClientKey(uint index)
        {
            m_KeyLocker.EnterWriteLock();
            m_clientsKey.Remove(index);
            m_KeyLocker.ExitWriteLock();
        }
        public bool HasClientKey(uint index)
        {
            int k;
            m_KeyLocker.EnterReadLock();
            bool has = m_clientsKey.TryGetValue(index, out k);
            m_KeyLocker.ExitReadLock();
            return has;
        }
        public bool IsClientKeyCorrect(uint index, int key)
        {
            int k;
            m_KeyLocker.EnterReadLock();
            bool has = m_clientsKey.TryGetValue(index, out k);
            m_KeyLocker.ExitReadLock();
            if (has == false)
            {
                Console.WriteLine("未找到key.Index:" + index.ToString());
            }
            return key == k;
        }
        #endregion
    }

    #region ClientSession
    public class ClientSession
    {
        internal KCPServer m_KCPServer;

        internal KCPLib m_Kcp;
        void init_kcp(UInt32 conv)
        {
            m_Kcp = new KCPLib(conv, (byte[] buf, int size) =>
            {
                m_KCPServer.Send(this, buf, 0, size);
            });

            // fast mode.
            m_Kcp.NoDelay(1, 10, 2, 1);
            m_Kcp.WndSize(128, 128);
        }

        private uint m_netIndex;
        /// <summary>
        /// 客户端连接索引conv(index)
        /// </summary>
        public uint NetIndex
        {
            get
            {
                return m_netIndex;
            }
        }
        public ClientSession(uint index)
        {
            init_kcp(index);
            m_netIndex = index;
        }

        public int Key { get; set; }
        public EndPoint @EndPoint { get; set; }

        ClientSessionStatus m_Status = ClientSessionStatus.InConnect;
        public ClientSessionStatus Status
        {
            get
            {
                return m_Status;
            }
            set
            {
                m_Status = value;
            }
        }


        /// <summary>
        /// 和Update同一个线程调用
        /// </summary>
        /// <param name="buf"></param>
        public void Send(byte[] buf)
        {
            m_Kcp.Send(buf, 0, buf.Length);
            m_NeedUpdateFlag = true;
        }

        /// <summary>
        /// 和Update同一个线程调用
        /// </summary>
        public void Send(string str)
        {
            byte[] buf = this.m_KCPServer.BytePool.Rent(32 * 1024);
            int bytes = System.Text.ASCIIEncoding.ASCII.GetBytes(str, 0, str.Length, buf, 0);
            Send(buf, 0, bytes);
            this.m_KCPServer.BytePool.Return(buf, false);
        }

        private void Send(byte[] buf, int offset, int bytes)
        {
            m_Kcp.Send(buf, offset, bytes);
            m_NeedUpdateFlag = true;
        }


        /// <summary>
        /// 由Server.Update来调用，经过KCP处理后，如果确认是客户端发来的信息，则调用m_KCPServer.OnRecvData
        /// </summary>
        /// GG：修改代码采用回调，不直接调用 m_KCPServer
        internal void process_recv_queue(SocketAsyncEventArgs e)
        {
#if DEV
            IRQLog.AppLog.Log(this.m_netIndex.ToString() + ",接收1");
#endif
            m_Kcp.Input(e.Buffer, e.Offset, e.BytesTransferred);

            m_NeedUpdateFlag = true;

            for (var size = m_Kcp.PeekSize(); size > 0; size = m_Kcp.PeekSize())
            {
                byte[] buffer;
                buffer = (UdpLibConfig.UseBytePool ? m_KCPServer.BytePool.Rent(size) : new byte[size]);
                try
                {

                    if (m_Kcp.Recv(buffer) > 0)
                    {
                        m_LastRecvTimestamp = m_KCPServer.m_watch.Elapsed;

                        uint key = 0;
                        KCPLib.ikcp_decode32u(buffer, 0, ref key);
                        if (m_KCPServer.IsClientKeyCorrect(this.m_netIndex, (int)key) == false)
                        {
#if DEBUG
                            Console.WriteLine("index:{0} key 不对", this.m_netIndex);
#endif
                            m_KCPServer.BytePool.Return(buffer, true);
                            DisposeReason = ClientSessionDisposeReason.IndexKeyError;
                            //key不对
                            Dispose();
                            return;
                        }
#if DEV
                    IRQLog.AppLog.Log(this.m_netIndex.ToString() + ",接收2");
#endif
                        m_KCPServer.OnRecvData(this, buffer, 0, size);
                    }
                }
                finally
                {
                    if (UdpLibConfig.UseBytePool)
                    {
                        m_KCPServer.BytePool.Return(buffer, true);
                    }
                }
            }
        }

        public ClientSessionDisposeReason DisposeReason = ClientSessionDisposeReason.None;
        private bool m_Disposed = false;
        /// <summary>
        /// 内部仅仅是标记一下，并没有真正Dispose，需要服务器来Dispose
        /// </summary>
        private void Dispose()
        {
            if (m_Disposed)
            {
                return;
            }
            m_Disposed = true;
            m_KCPServer.AddToDisposedQueue(this);
        }

        /// <summary>
        /// 最后收到数据的时刻。
        /// 当超过UdpLibConfig.MaxTimeNoData时间没有收到客户端的数据，则可以认为是死链接
        /// </summary>
        internal TimeSpan m_LastRecvTimestamp;
        /// <summary>
        /// 仅仅处理KCP时钟，判断是否好久没有收到数据。
        /// </summary>
        public void Update()
        {
            SmartUpdateKCP(KCPServer.iclock());
            if (m_KCPServer.m_watch.Elapsed - m_LastRecvTimestamp > UdpLibConfig.MaxTimeNoData)
            {
                DisposeReason = ClientSessionDisposeReason.MaxTimeNoData;
                Dispose();
            }
        }

        private bool m_NeedUpdateFlag = false;
        private UInt32 m_NextUpdateTime;
        /// <summary>
        /// 仅仅提供m_kcp的时钟。
        /// </summary>
        void SmartUpdateKCP(UInt32 current)
        {
            if (m_Status != ClientSessionStatus.Connected)
            {
                return;
            }
            if (m_NeedUpdateFlag || current >= m_NextUpdateTime)
            {
                m_Kcp.Update(current);
                m_NextUpdateTime = m_Kcp.Check(current);
                m_NeedUpdateFlag = false;
            }
        }


        public void Close()
        {
            //mUdpServer.Close();
        }

        /// <summary>
        /// 没有使用
        /// </summary>
        internal void ResetKCP()
        {
            init_kcp(m_netIndex);
        }
    }

    public enum ClientSessionDisposeReason
    {
        None = 0,
        Normal,
        IndexKeyError,
        MaxTimeNoData
    }
    #endregion
    /// <summary>
    /// 新客户端接口，例子中没有真正使用
    /// </summary>
    public interface INewClientSessionProcessor
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="index"></param>
        /// <param name="remoteEndPoint"></param>
        /// <returns>如果为false，则丢弃</returns>
        bool OnNewSession(uint index, EndPoint remoteEndPoint);
    }
}
#endif