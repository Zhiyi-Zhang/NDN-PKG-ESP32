#ifndef ESP8266NDN_BOOTSTRAP_CLIENT_HPP
#define ESP8266NDN_BOOTSTRAP_CLIENT_HPP

#include "../core/face.hpp"

namespace ndn {

/** \brief NDN reachability test tool client side
 */
class BootstrapClient
{
public:

  BootstrapClient(Face& face, int bootstrapInterval, int bootstrapTimeout = -1);

  /** \brief loop the client
   */
  void
  loop();


  bool
  processBootstrapResponse(const DataLite& data);


  bool
  processCeritificateResponse(const DataLite& data);


  bool
  processNack(const NetworkNackLite& nack, const InterestLite& interest);

  /** \brief send a probe now
   *  \note Response or timeout for previous probe will be ignored.
   */
  bool
  BootstrapRequest();

  bool 
  CertificateRequest();

  enum class Event {
    NONE,
    BOOTSTRAP_REQUEST,
    CERTIFICATE_REQUEST,
    BOOTSTRAP_RESPONSE,
    CERTIFICATE_RESPONSE,
    TIMEOUT,
    NACK,
  };

  
  typedef void (*EventCallback)(void* arg, Event evt);

  /** \brief set event handler
   *
   *  Only one handler is allowed. This overwrites any previous handler setting.
   */
  void
  onEvent(EventCallback cb, void* cbarg)
  {
    m_evtCb = cb;
    m_evtCbArg = cbarg;
  }

private:
  
  void setDefaultCertificate();

  void setCertificate();

  void setAchorCertificate();

  void setAnchorPubKey(const uint8_t* keybits);

private:
  Face& m_face;
  const int m_bootstrapInterval;
  const int m_bootstrapTimeout;
  unsigned long m_lastProbe; ///< timestamp of last probe
  bool m_isPending; ///< whether lastProbe is waiting for either response or timeout
  EventCallback m_evtCb;
  void* m_evtCbArg;
  
  
  
  DataLite m_anchorCertificate;
  DataLite m_Certificate;
  EcPrivateKey m_bopvt;
  EcPublicKey m_bopub;
  EcPrivateKey* m_ckpvt;
  EcPublicKey* m_ckpub;
  EcPublicKey* m_anchorpub;

};

} // namespace ndn

#endif // ESP8266NDN_PING_CLIENT_HPP