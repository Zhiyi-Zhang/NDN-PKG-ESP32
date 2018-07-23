#include "bootstrap-client.hpp"
#include "../core/logger.hpp"
#include "../ndn-cpp/c/util/crypto.h"

#define BOOTSTRAPCLIENT_DBG(...) DBG(BootstrapClient, __VA_ARGS__)

namespace ndn {

static inline int
determineTimeout(int bootstrapTimeout, const InterestLite& interest)
{
  if (bootstrapTimeout > 0) {
    return bootstrapTimeout;
  }
  if (interest.getInterestLifetimeMilliseconds() < 0.0) {
    return 4000;
  }
  return static_cast<int>(interest.getInterestLifetimeMilliseconds());
}

BootstrapClient::BootstrapClient(Face& face, int bootstrapInterval, int bootstrapTimeout = -1,
                                 EcPublicKey& BootstrapPub, EcPrivateKey& BootstrapPvt)
  : m_face(face)
  , m_bootstrapInterval(bootstrapInterval)
  , m_bootstrapTimeout(determineTimeout(bootstrapTimeout, interest))
  , m_lastProbe(millis())
  , m_isPending(false)
  , m_evtCb(nullptr)
  , m_bopub(BootstrapPub)
  , m_bopvt(BootstrapPvt)
  , m_anchorpub(nullptr)
  , m_ckpub(nullptr)
  , m_ckpvt(nullptr)
  , 
{
  if (m_bootstrapInterval <= m_bootstrapTimeout) {
    BOOTSTRAPCLIENT_DBG(F("ERROR: interval should be greater than timeout"));
  }
}

void
BootstrapClient::loop()
{
  unsigned long now = millis();
  if (m_isPending && now - m_lastProbe > m_bootstrapTimeout) {
    m_isPending = false;
    BOOTSTRAPCLIENT_DBG(F("timeout"));
    if (m_evtCb != nullptr) {
      m_evtCb(m_evtCbArg, Event::TIMEOUT);
    }
  }

  if ((now - m_lastProbe > m_bootstrapInterval) && (!m_anchorpub)) {
    this->BootstrapRequest();
  }
}

bool
BootstrapClient::processBootstrapResponse(const DataLite& data)  //TODO: move the logic from riot to here
{  
  if (!m_interest.getName().match(data.getName())) {
    return false;
  }
  m_isPending = false;

  BOOTSTRAPCLIENT_DBG(F("bootstrap response received  ") << F(" rtt=") << _DEC(millis() - m_lastProbe));
  if (m_evtCb != nullptr) {
    m_evtCb(m_evtCbArg, Event::BOOTSTAP_RESPONSE);
  }

  //Notice: Copy from ndn-riot
   /* 
    Incoming Packet Format
    Name: echo of I1->append /version
    Content: token
             BKpub digest
             anchor certificate
                               Name:  anchor prefix
                               Content： AKpub
                               Signature: AKpri
    Signature: AKpri
    */

    auto Content = data.getContent();
    uint8_t* buf = Content.buf();
    int len = Content.size();

    //read the token

    //verify the BKpub

    //install the m_anchorCertificate from embedded data packet

    m_anchorCertificate = data_anchor.getContent();

    //get certificate name - home prefix
    home_prefix = m_anchorCertificate.getName();
    
    auto akpub = m_anchorCertificate.getContent();

    uint8_t* anchor_pub_key = (uint8_t*)malloc(64);
    memcpy(anchor_pub_key, ak.buf + 4, 64)
    
    m_anchorpub = new EcPublicKey(anchor_pub_key);
    //verify anchor's signature
    m_face.verifyData(*m_anchorpub);

  return true;
}

bool
BootstrapClient::processCertificateResponse(const DataLite& data)  //TODO: move the logic from riot to here
{
  
  if (!m_interest.getName().match(data.getName())) {
    return false;
  }
  m_isPending = false;

  BOOTSTRAPCLIENT_DBG(F("certificate response received  ") << F(" rtt=") << _DEC(millis() - m_lastProbe));
  if (m_evtCb != nullptr) {
    m_evtCb(m_evtCbArg, Event::CERTIFICATE_RESPONSE);
  }

  //verify the signature  
  m_face.verifyData(*m_anchorpub);

  //install the certificate
  m_Certificate = data.getContent();
        
  //we need extract the Datalite from Bloblite
  
  data_cert.getName(); //use the whole name as identity and keyname
        
  return true;
}

bool
BootstrapClient::processNack(const NetworkNackLite& nack, const InterestLite& interest) 
  if (!m_interest.getName().equals(interest.getName())) {
    return false;
  }
  m_isPending = false;

  PINGCLIENT_DBG(F("nack seq=") << _HEX(seq) << F(" rtt=") << _DEC(millis() - m_lastProbe));
  if (m_evtCb != nullptr) {
    m_evtCb(m_evtCbArg, Event::NACK, seq);
  }

  return true;
}

bool
BootstrapClient::BootstrapRequest()  //TODO: move the logic from riot to here
{
    // /ndn/sign-on/{digest of BKpub}/{ECDSA signature by BKpri}

    //get default certificate
    setDefaultCertificate();

    // /ndn/sign-on
    const char* uri1 = "ndn";
    const char* uri2 = "sign-on";

    Component array[2]={Component(uri1, sizeof(uri1)), Component(uri2, sizeof(uri2)};
    NameLite name(array, 2);
    
    //{digest of BKpub}
    util::CryptoLite;
    uint8_t* digest_BKpub = (uint8_t*)malloc(32);
    CryptoLite::digestSha256(m_bopub, 64, digest_BKpub);
    name.appendImplicitSha256Digest(digest_BKpub, 32);

    auto BootstrapReq = InterestLite(name, 2_s);
    BootstrapReq.setMustBeFresh(true);

    BOOTSTRAPCLIENT_DBG(F("bootstrap interest name: ") << _HEX(name));

    // send the signed interest
    m_face.setSigningKey(m_bopvt);
    m_face.sendSignedInterest(BootstrapReq);

    m_isPending = true;
    m_lastProbe = millis();

    if (m_evtCb != nullptr) {
      m_evtCb(m_evtCbArg, Event::BOOTSTRAP_REQUEST);
  }
}

bool
BootstrapClient::CertificateRequest(const NameLite& prefix, const uint64_t& token)   //TODO: move the logic from riot to here
{


    // /[home-prefix]/cert/{digest of BKpub}/{CKpub}/{signature of token}/{signature by BKpri}
    Component cert = "cert";
    prefix.append(cert);

    //{digest of BKpub}
    util::CryptoLite;
    uint8_t* digest_BKpub_cert = (uint8_t*)malloc(32);
    CryptoLite::digestSha256(m_bopub, 64, digest_BKpub);
    prefix.appendImplicitSha256Digest(digest_BKpub_cert, 32);
    free(digest_BKpub_cert);
    
    //{CKpub}
    // here we don't have APIs to generate key pair, so we generate it manualy
    uint8_t* ck_pub = (uint8_t*)malloc(64);
    uint8_t* ck_pvt = (uint8_t*)malloc(32);
    uECC_make_key(ck_pub, ck_pvt);
    m_ckpvt = new ckpvt(ck_pvt);
    m_ckpub = new ckpub(ck_pub);
    prefix.append(ck_pub, 64);

    //{signature of token}
    // here we only have APIs designed to sign with siginfo, so we implement it manualy
    uint8_t* sigToken = (uint8_t*)malloc(64 + 2);
    int sigLen = m_signingKey->sign(&token, 8, sigToken);
    sigToken[0] = ndn_Tlv_SignatureValue;
    sigToken[1] = sigLen;
    prefix.append(sigToken, 64 + 2);

    //{signature by BKpri}
    auto BootstrapReq = InterestLite(prefix, 2_s);
    BootstrapReq.setMustBeFresh(true);

    BOOTSTRAPCLIENT_DBG(F("bootstrap interest name: ") << _HEX(prefix));

    m_face.setSigningKey(m_bopvt);
    m_face.sendSignedInterest(BootstrapReq);

    m_isPending = true;
    m_lastProbe = millis();

    if (m_evtCb != nullptr) {
      m_evtCb(m_evtCbArg, Event::BOOTSTRAP_REQUEST);
}

} // namespace ndn