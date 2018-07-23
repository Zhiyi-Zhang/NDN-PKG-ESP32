#include "bootstrap-client.hpp"
#include "../core/logger.hpp"
#include "../ndn-cpp/c/util/crypto.h"

#define BOOTSTRAPCLIENT_DBG(...) DBG(BootstrapClient, __VA_ARGS__)

namespace ndn {

BootstrapClient::BootstrapClient(Face& face, NameLite& host,
                                 EcPublicKey& BootstrapPub, EcPrivateKey& BootstrapPvt)
  : m_face(face)
  , m_lastProbe(millis())
  , m_isPending(false)
  , m_evtCb(nullptr)
  , m_bopub(BootstrapPub)
  , m_bopvt(BootstrapPvt)
  , m_anchorpub(nullptr)
  , m_ckpub(nullptr)
  , m_ckpvt(nullptr)
  , m_host(host)
  , m_token(nullptr)
{
    //TODO: we should add something here
}

void
BootstrapClient::loop()
{
    //TODO: we should add timeout here
    this->BootstrapRequest();
  
}

bool
BootstrapClient::processBootstrapResponse(const DataLite& data)  
{  
  m_isPending = false;

  BOOTSTRAPCLIENT_DBG(F("bootstrap response received  ") << F(" rtt=") << _DEC(millis() - m_lastProbe));
  if (m_evtCb != nullptr) {
    m_evtCb(m_evtCbArg, Event::BOOTSTAP_RESPONSE);
  }

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
    BlobLite token(buf + 2, 10);
    m_token = &token;  
    buf += 10；
    len -= 10;

    //TODO: verify the BKpub
    buf += 34;
    len -=34;

    m_anchorCertificate = data_anchor.getContent();

    
    //TODO:  extract (NameLite)m_home_prefix in and (BlobLite)ak from m_anchorCertificate 


    uint8_t anchor_pub_key[64];
    memcpy(anchor_pub_key, /*ak.buf*/, 64);
    
    EcPublicKey acpub(anchor_pub_key);
    m_anchorpub = &acpub;
    //verify anchor's signature
    m_face.verifyData(*m_anchorpub);

  return true;
}

bool
BootstrapClient::processCertificateResponse(const DataLite& data)  
{
  m_isPending = false;

  BOOTSTRAPCLIENT_DBG(F("certificate response received  ") << F(" rtt=") << _DEC(millis() - m_lastProbe));
  if (m_evtCb != nullptr) {
    m_evtCb(m_evtCbArg, Event::CERTIFICATE_RESPONSE);
  }

  //verify the signature  
  m_face.verifyData(*m_anchorpub);

  //install the certificate  
  m_Certificate = data.getContent();
        
  return true;
}

bool
BootstrapClient::processNack(const NetworkNackLite& nack, const InterestLite& interest) 
{
  m_isPending = false;

  PINGCLIENT_DBG(F("nack seq=") << _HEX(seq) << F(" rtt=") << _DEC(millis() - m_lastProbe));
  if (m_evtCb != nullptr) {
    m_evtCb(m_evtCbArg, Event::NACK, seq);
  }

  return true;
}

bool
BootstrapClient::BootstrapRequest()  
{
    // /ndn/sign-on/{digest of BKpub}/{ECDSA signature by BKpri}

    // /ndn/sign-on
    const char* uri1 = "ndn";
    const char* uri2 = "sign-on";

    NameLite::Component array[2]={Component(uri1, sizeof(uri1)), Component(uri2, sizeof(uri2)};
    NameLite name(array, 2);
    
    //{digest of BKpub}
    util::CryptoLite;
    uint8_t* digest_BKpub = (uint8_t*)malloc(32);
    CryptoLite::digestSha256(m_bopub, 64, digest_BKpub);
    name.appendImplicitSha256Digest(digest_BKpub, 32);
    free(digest_BKpub);

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
BootstrapClient::CertificateRequest()   
{
    // /[home-prefix]/cert/{digest of BKpub}/{CKpub}/{signature of token}/{signature by BKpri}
    Component cert = "cert";
    NameLite prefix;
    prefix.set(m_home_prefix);
    prefix.append(cert);

    //{digest of BKpub}
    util::CryptoLite;
    uint8_t* digest_BKpub_cert = (uint8_t*)malloc(32);
    CryptoLite::digestSha256(m_bopub, 64, digest_BKpub);
    prefix.appendImplicitSha256Digest(digest_BKpub_cert, 32);
    free(digest_BKpub_cert);
    
    //{CKpub}
    // here we don't have APIs to generate key pair, so we generate it manualy
    uint8_t ck_pub[64];
    uint8_t ck_pvt[32];
    uECC_make_key(ck_pub, ck_pvt);
    EcPrivateKey ckpvt(ck_pvt, keyName); //TODO: we need name here
    EcPublicKey ckpub(ck_pub);
    m_ckpvt = &ckpvt;
    m_ckpub = &ckpub;
    prefix.append(ck_pub, 64);

    //{signature of token}
    // here we only have APIs designed to sign with siginfo, so we implement it manualy
    uint8_t* sigToken = (uint8_t*)malloc(64 + 2);
    int sigLen = m_signingKey->sign(m_token->buf() + 2, 8, sigToken);
    sigToken[0] = ndn_Tlv_SignatureValue;
    sigToken[1] = sigLen;
    prefix.append(sigToken, 64 + 2);
    free(sigToken);

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