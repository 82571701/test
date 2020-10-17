
#include <stdlib.h> // for atoi

#include <string>
#include <iostream>
#include <thread>
#include <memory>
#include <mutex>

#include <openvpn/common/platform.hpp>

#ifdef OPENVPN_PLATFORM_MAC
#include <CoreFoundation/CFBundle.h>
#include <ApplicationServices/ApplicationServices.h>
#endif

#ifdef OPENVPN_USE_LOG_BASE_SIMPLE
#define OPENVPN_LOG_GLOBAL // use global rather than thread-local log object pointer
#include <openvpn/log/logbasesimple.hpp>
#endif

// don't export core symbols
#define OPENVPN_CORE_API_VISIBILITY_HIDDEN

// use SITNL on Linux by default
#if defined(OPENVPN_PLATFORM_LINUX) && !defined(OPENVPN_USE_IPROUTE2) && !defined(OPENVPN_USE_SITNL)
#define OPENVPN_USE_SITNL
#endif


#include <client/ovpncli.cpp>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/signal.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/common/getopt.hpp>
#include <openvpn/common/getpw.hpp>
#include <openvpn/common/cleanup.hpp>
#include <openvpn/time/timestr.hpp>
#include <openvpn/ssl/peerinfo.hpp>
#include <openvpn/ssl/sslchoose.hpp>

#ifdef OPENVPN_REMOTE_OVERRIDE
#include <openvpn/common/process.hpp>
#endif


#if defined(USE_MBEDTLS)
#include <openvpn/mbedtls/util/pkcs1.hpp>
#endif

#if defined(OPENVPN_PLATFORM_WIN)
#include <openvpn/win/console.hpp>
#include <shellapi.h>
#endif

#ifdef USE_NETCFG
#include "client/core-client-netcfg.hpp"
#endif

#if defined(OPENVPN_PLATFORM_LINUX)

#include <openvpn/tun/linux/client/tuncli.hpp>

// we use a static polymorphism and define a
// platform-specific TunSetup class, responsible
// for setting up tun device
#define TUN_CLASS_SETUP TunLinuxSetup::Setup<TUN_LINUX>
#include <openvpn/tun/linux/client/tuncli.hpp>
#elif defined(OPENVPN_PLATFORM_MAC)
#include <openvpn/tun/mac/client/tuncli.hpp>
#define TUN_CLASS_SETUP TunMac::Setup
#endif

#include <QFile>
#include <QString>

using namespace openvpn;

namespace {
  OPENVPN_SIMPLE_EXCEPTION(usage);
}


#ifdef USE_TUN_BUILDER
class ClientBase : public ClientAPI::OpenVPNClient
{
public:
  bool tun_builder_new() override
  {
    tbc.tun_builder_set_mtu(1500);
    return true;
  }

  int tun_builder_establish() override
  {
    if (!tun)
      {
    tun.reset(new TUN_CLASS_SETUP());
      }

    TUN_CLASS_SETUP::Config config;
    config.layer = Layer(Layer::Type::OSI_LAYER_3);
    // no need to add bypass routes on establish since we do it on socket_protect
    config.add_bypass_routes_on_establish = false;
    return tun->establish(tbc, &config, nullptr, std::cout);
  }

  bool tun_builder_add_address(const std::string& address,
                   int prefix_length,
                   const std::string& gateway, // optional
                   bool ipv6,
                   bool net30) override
  {
    return tbc.tun_builder_add_address(address, prefix_length, gateway, ipv6, net30);
  }

  bool tun_builder_add_route(const std::string& address,
                 int prefix_length,
                 int metric,
                 bool ipv6) override
  {
    return tbc.tun_builder_add_route(address, prefix_length, metric, ipv6);
  }

  bool tun_builder_reroute_gw(bool ipv4,
                  bool ipv6,
                  unsigned int flags) override
  {
    return tbc.tun_builder_reroute_gw(ipv4, ipv6, flags);
  }

  bool tun_builder_set_remote_address(const std::string& address,
                      bool ipv6) override
  {
    return tbc.tun_builder_set_remote_address(address, ipv6);
  }

  bool tun_builder_set_session_name(const std::string& name) override
  {
    return tbc.tun_builder_set_session_name(name);
  }

  bool tun_builder_add_dns_server(const std::string& address, bool ipv6) override
  {
    return tbc.tun_builder_add_dns_server(address, ipv6);
  }

  void tun_builder_teardown(bool disconnect) override
  {
    std::ostringstream os;
    auto os_print = Cleanup([&os](){ OPENVPN_LOG_STRING(os.str()); });
    tun->destroy(os);
  }

  bool socket_protect(int socket, std::string remote, bool ipv6) override
  {
    (void)socket;
    std::ostringstream os;
    auto os_print = Cleanup([&os](){ OPENVPN_LOG_STRING(os.str()); });
    return tun->add_bypass_route(remote, ipv6, os);
  }

private:
  TUN_CLASS_SETUP::Ptr tun = new TUN_CLASS_SETUP();
  TunBuilderCapture tbc;
};
#else // USE_TUN_BUILDER
class ClientBase : public ClientAPI::OpenVPNClient
{
public:
  bool socket_protect(int socket, std::string remote, bool ipv6) override
  {
    std::cout << "NOT IMPLEMENTED: *** socket_protect " << socket << " " << remote << std::endl;
    return true;
  }
};
#endif

class Client : public ClientBase
{
public:
  enum ClockTickAction {
    CT_UNDEF,
    CT_STOP,
    CT_RECONNECT,
    CT_PAUSE,
    CT_RESUME,
    CT_STATS,
  };

  bool is_dynamic_challenge() const
    {
      return !dc_cookie.empty();
    }

  std::string dynamic_challenge_cookie()
    {
      return dc_cookie;
    }

//  std::string read_profile(QString fileName)
//  {
//      QFile file(fileName);
//          if(file.open(QIODevice::ReadOnly | QIODevice::Text))
//             {
//                 QByteArray t ;
//                 while(!file.atEnd())
//                 {
//                     t += file.readLine();
//                 }
//                 file.close();
//                 char *ch;
//                 ch = t.data();
//                 return ch;
//             }
//          return  nullptr;
//  }

    std::string epki_ca;
    std::string epki_cert;
  #if defined(USE_MBEDTLS)
    MbedTLSPKI::PKContext epki_ctx; // external PKI context
  #endif

    void set_clock_tick_action(const ClockTickAction action)
    {
      clock_tick_action = action;
    }

    void print_stats()
    {
      const int n = stats_n();
      std::vector<long long> stats = stats_bundle();

      std::cout << "STATS:" << std::endl;
      for (int i = 0; i < n; ++i)
        {
      const long long value = stats[i];
      if (value)
        std::cout << "  " << stats_name(i) << " : " << value << std::endl;
        }
    }

  #ifdef OPENVPN_REMOTE_OVERRIDE
    void set_remote_override_cmd(const std::string& cmd)
    {
      remote_override_cmd = cmd;
    }
  #endif

    void set_write_url_fn(const std::string& fn)
    {
      write_url_fn = fn;
    }

  private:
    virtual void event(const ClientAPI::Event& ev) override
    {
      std::cout << date_time() << " EVENT: " << ev.name;
      if (!ev.info.empty())
        std::cout << ' ' << ev.info;
      if (ev.fatal)
        std::cout << " [FATAL-ERR]";
      else if (ev.error)
        std::cout << " [ERR]";
      std::cout << std::endl;
      if (ev.name == "DYNAMIC_CHALLENGE")
        {
      dc_cookie = ev.info;

      ClientAPI::DynamicChallenge dc;
      if (ClientAPI::OpenVPNClient::parse_dynamic_challenge(ev.info, dc)) {
        std::cout << "DYNAMIC CHALLENGE" << std::endl;
        std::cout << "challenge: " << dc.challenge << std::endl;
        std::cout << "echo: " << dc.echo << std::endl;
        std::cout << "responseRequired: " << dc.responseRequired << std::endl;
        std::cout << "stateID: " << dc.stateID << std::endl;
      }
        }
      else if (ev.name == "INFO" && (string::starts_with(ev.info, "OPEN_URL:http://")
                  || string::starts_with(ev.info, "OPEN_URL:https://")))
        {
      // launch URL
      const std::string url_str = ev.info.substr(9);

      if (!write_url_fn.empty())
        write_string(write_url_fn, url_str + '\n');

  #ifdef OPENVPN_PLATFORM_MAC
      std::thread thr([url_str]() {
          CFURLRef url = CFURLCreateWithBytes(
              NULL,                        // allocator
          (UInt8*)url_str.c_str(),     // URLBytes
          url_str.length(),            // length
          kCFStringEncodingUTF8,       // encoding
          NULL                         // baseURL
          );
          LSOpenCFURLRef(url, 0);
          CFRelease(url);
        });
      thr.detach();
  #else
      std::cout << "No implementation to launch " << url_str << std::endl;
  #endif
        }
    }

    virtual void log(const ClientAPI::LogInfo& log) override
    {
      std::lock_guard<std::mutex> lock(log_mutex);
      std::cout << date_time() << ' ' << log.text << std::flush;
    }

    virtual void clock_tick() override
    {
      const ClockTickAction action = clock_tick_action;
      clock_tick_action = CT_UNDEF;

      switch (action)
        {
        case CT_STOP:
      std::cout << "signal: CT_STOP" << std::endl;
      stop();
      break;
        case CT_RECONNECT:
      std::cout << "signal: CT_RECONNECT" << std::endl;
      reconnect(0);
      break;
        case CT_PAUSE:
      std::cout << "signal: CT_PAUSE" << std::endl;
      pause("clock-tick pause");
      break;
        case CT_RESUME:
      std::cout << "signal: CT_RESUME" << std::endl;
      resume();
      break;
        case CT_STATS:
      std::cout << "signal: CT_STATS" << std::endl;
      print_stats();
      break;
        default:
      break;
        }
    }

    virtual void external_pki_cert_request(ClientAPI::ExternalPKICertRequest& certreq) override
    {
      if (!epki_cert.empty())
        {
      certreq.cert = epki_cert;
      certreq.supportingChain = epki_ca;
        }
      else
        {
      certreq.error = true;
      certreq.errorText = "external_pki_cert_request not implemented";
        }
    }

    virtual void external_pki_sign_request(ClientAPI::ExternalPKISignRequest& signreq) override
    {
  #if defined(USE_MBEDTLS)
      if (epki_ctx.defined())
        {
      try {
        // decode base64 sign request
        BufferAllocated signdata(256, BufferAllocated::GROW);
        base64->decode(signdata, signreq.data);

        // get MD alg
        const mbedtls_md_type_t md_alg = PKCS1::DigestPrefix::MbedTLSParse().alg_from_prefix(signdata);

        // log info
        OPENVPN_LOG("SIGN[" << PKCS1::DigestPrefix::MbedTLSParse::to_string(md_alg) << ',' << signdata.size() << "]: " << render_hex_generic(signdata));

        // allocate buffer for signature
        BufferAllocated sig(mbedtls_pk_get_len(epki_ctx.get()), BufferAllocated::ARRAY);

        // sign it
        size_t sig_size = 0;
        const int status = mbedtls_pk_sign(epki_ctx.get(),
                           md_alg,
                           signdata.c_data(),
                           signdata.size(),
                           sig.data(),
                           &sig_size,
                           rng_callback,
                           this);
        if (status != 0)
          throw Exception("mbedtls_pk_sign failed, err=" + openvpn::to_string(status));
        if (sig.size() != sig_size)
          throw Exception("unexpected signature size");

        // encode base64 signature
        signreq.sig = base64->encode(sig);
        OPENVPN_LOG("SIGNATURE[" << sig_size << "]: " << signreq.sig);
      }
      catch (const std::exception& e)
        {
          signreq.error = true;
          signreq.errorText = std::string("external_pki_sign_request: ") + e.what();
        }
        }
      else
  #endif
        {
      signreq.error = true;
      signreq.errorText = "external_pki_sign_request not implemented";
        }
    }

    // RNG callback
    static int rng_callback(void *arg, unsigned char *data, size_t len)
    {
      Client *self = (Client *)arg;
      if (!self->rng)
        {
      self->rng.reset(new SSLLib::RandomAPI(false));
      self->rng->assert_crypto();
        }
      return self->rng->rand_bytes_noexcept(data, len) ? 0 : -1; // using -1 as a general-purpose mbed TLS error code
    }

    virtual bool pause_on_connection_timeout() override
    {
      return false;
    }

  #ifdef OPENVPN_REMOTE_OVERRIDE
    virtual bool remote_override_enabled() override
    {
      return !remote_override_cmd.empty();
    }

    virtual void remote_override(ClientAPI::RemoteOverride& ro)
    {
      RedirectPipe::InOut pio;
      Argv argv;
      argv.emplace_back(remote_override_cmd);
      OPENVPN_LOG(argv.to_string());
      const int status = system_cmd(remote_override_cmd,
                    argv,
                    nullptr,
                    pio,
                    RedirectPipe::IGNORE_ERR,
                    nullptr);
      if (!status)
        {
      const std::string out = string::first_line(pio.out);
      OPENVPN_LOG("REMOTE OVERRIDE: " << out);
      auto svec = string::split(out, ',');
      if (svec.size() == 4)
        {
          ro.host = svec[0];
          ro.ip = svec[1];
          ro.port = svec[2];
          ro.proto = svec[3];
        }
      else
        ro.error = "cannot parse remote-override, expecting host,ip,port,proto (at least one or both of host and ip must be defined)";
        }
      else
        ro.error = "status=" + std::to_string(status);
    }
  #endif

    std::mutex log_mutex;
    std::string dc_cookie;
    RandomAPI::Ptr rng;      // random data source for epki
    volatile ClockTickAction clock_tick_action = CT_UNDEF;

  #ifdef OPENVPN_REMOTE_OVERRIDE
    std::string remote_override_cmd;
  #endif

    std::string write_url_fn;
};

static Client *the_client = nullptr; // GLOBAL

static std::string read_profile(QString fileName)
{
    //char *ch = nullptr;
    QFile file(fileName);
        if(file.open(QIODevice::ReadOnly | QIODevice::Text))
           {
               QByteArray t ;
               while(!file.atEnd())
               {
                   t += file.readLine();
               }
               file.close();
               char *ch;
               ch = t.data();
               return ch;
           }
        return  nullptr;
}

static void worker_thread()
{
#if !defined(OPENVPN_OVPNCLI_SINGLE_THREAD)
  openvpn_io::detail::signal_blocker signal_blocker; // signals should be handled by parent thread
#endif
  try {
    std::cout << "Thread starting..." << std::endl;
    ClientAPI::Status connect_status = the_client->connect();
    if (connect_status.error)
      {
    std::cout << "connect error: ";
    if (!connect_status.status.empty())
      std::cout << connect_status.status << ": ";
    std::cout << connect_status.message << std::endl;
      }
  }
  catch (const std::exception& e)
    {
      std::cout << "Connect thread exception: " << e.what() << std::endl;
    }
  std::cout << "Thread finished" << std::endl;
}

static void start_thread(Client& client)
{
  std::unique_ptr<std::thread> thread;

  // start connect thread
  the_client = &client;
  thread.reset(new std::thread([]() {
    worker_thread();
      }));

  {
    // catch signals that might occur while we're in join()
    //Signal signal(handler, Signal::F_SIGINT|Signal::F_SIGTERM|Signal::F_SIGHUP|Signal::F_SIGUSR1|Signal::F_SIGUSR2);

    // wait for connect thread to exit
    thread->join();
  }
  the_client = nullptr;
}

static void OpenClient()
{
    auto cleanup = Cleanup([]() {
          the_client = nullptr;
        });

    std::string username = "luoxin";
        std::string password = "luoxin";
        std::string response;
        std::string dynamicChallengeCookie;
        std::string proto;
        std::string ipv6;
        std::string server;
        std::string port;
        int timeout = 0;
        std::string compress;
        std::string privateKeyPassword;
        std::string tlsVersionMinOverride;
        std::string tlsCertProfileOverride;
        std::string proxyHost;
        std::string proxyPort;
        std::string proxyUsername;
        std::string proxyPassword;
        std::string peer_info;
        std::string gremlin;
        bool disableClientCert = false;
        bool proxyAllowCleartextAuth = false;
        int defaultKeyDirection = -1;
        bool forceAesCbcCiphersuites = false;
        int sslDebugLevel = 0;
        bool googleDnsFallback = false;
        bool autologinSessions = false;
        bool retryOnAuthFailed = false;
        bool tunPersist = false;
#if defined (Q_OS_WIN)
    bool wintun = false;
#elif
           bool wintun = true;
#endif

        bool merge = false;
        bool version = false;
        bool altProxy = false;
        bool dco = false;


    ClientAPI::Config config;
    //config.guiVersion = "cli 1.0";
    #if defined(OPENVPN_PLATFORM_WIN)
//              int nargs = 0;
//              auto argvw = CommandLineToArgvW(GetCommandLineW(), &nargs);
//              UTF8 utf8(Win::utf8(argvw[nargs - 1]));
//              config.content = read_profile(utf8.get(), profile_content);
        config.content = read_profile(":/openvpnClient/ovpn_demo.ovpn");
    #else
        config.content = read_profile(":/openvpnClient/ovpn_demo.ovpn");

    #endif

        config.serverOverride = server;
                  config.portOverride = port;
                  config.protoOverride = proto;
                  config.connTimeout = timeout;
                  config.compressionMode = compress;
                  config.ipv6 = ipv6;
                  config.privateKeyPassword = privateKeyPassword;
                  config.tlsVersionMinOverride = tlsVersionMinOverride;
                  config.tlsCertProfileOverride = tlsCertProfileOverride;
                  config.disableClientCert = disableClientCert;
                  config.proxyHost = proxyHost;
                  config.proxyPort = proxyPort;
                  config.proxyUsername = proxyUsername;
                  config.proxyPassword = proxyPassword;
                  config.proxyAllowCleartextAuth = proxyAllowCleartextAuth;
                  config.altProxy = altProxy;
                  config.dco = dco;
                  config.defaultKeyDirection = defaultKeyDirection;
                  config.forceAesCbcCiphersuites = forceAesCbcCiphersuites;
                  config.sslDebugLevel = sslDebugLevel;
                  config.googleDnsFallback = googleDnsFallback;
                  config.autologinSessions = autologinSessions;
                  config.retryOnAuthFailed = retryOnAuthFailed;
                  config.tunPersist = tunPersist;
                  config.gremlinConfig = gremlin;
                  config.info = true;
                  config.wintun = wintun;
                  config.ssoMethods = "openurl";

        //config.tunPersist = true;
        Client client;
       // config.content = client.read_profile(":/openvpnClient/ovpn_demo.ovpn");
        ClientAPI::ProvideCreds creds;
        creds.username = "luoxin";
        creds.password = "luoxin";
        ClientAPI::Status creds_status = client.provide_creds(creds);
          if (creds_status.error)
          {
                OPENVPN_THROW_EXCEPTION("creds error: " << creds_status.message);
        }
        const ClientAPI::EvalConfig eval = client.eval_config(config);
        if (eval.error)
                    OPENVPN_THROW_EXCEPTION("eval config error: " << eval.message);



                     std::cout << "CONNECTING..." << std::endl;

                     // start the client thread
                     //start_thread(client);
                     the_client = &client;

                     try {
                       std::cout << "starting..." << std::endl;
                       ClientAPI::Status connect_status = the_client->connect();
                       if (connect_status.error)
                         {
                       std::cout << "connect error: ";
                       if (!connect_status.status.empty())
                         std::cout << connect_status.status << ": ";
                       std::cout << connect_status.message << std::endl;
                         }
                     }
                     catch (const std::exception& e)
                       {
                         std::cout << "Connect thread exception: " << e.what() << std::endl;
                       }
                     std::cout << "finished" << std::endl;

}


