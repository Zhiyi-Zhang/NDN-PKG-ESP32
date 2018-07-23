#ifdef ESP32
// extras/BleClient.py is a client that can connect to this ndnping server.

#include <esp8266ndn.h>

char PREFIX[] = "/example/esp32-ble/ping";
const int LED0 = 15;

ndn::BleServerTransport g_transport;
ndn::Face g_face(g_transport);
ndn::DigestKey g_pvtkey;

ndn_NameComponent g_comps[4];
ndn::NameLite g_prefix(g_comps, 4);
ndn::BootstrapClient g_client(g_face, g_prefix);

//initializing the marker
static bool BootRes = false;
static bool CertRes = false;

void
processData(void*, const ndn::DataLite& data, uint64_t)
{
  if(!(BootRes && CertRes))
  {
    Serial.print("> Bootstrap Response");
    g_client0.processBootstrapResponse(data);
    BootRes = true;
    g_client0.CertificateRequest();
  }
  if(BootRes)
  {
    Serial.print("> Certificate Response");
    g_client0.processCertificateResponse(data);
    CertRes = true;
  }
}

void
processNack(void*, const ndn::NetworkNackLite& nack, const ndn::InterestLite& interest, uint64_t)
{
  Serial.print("> NACK");
  g_client0.processNack(nack, interest);
}

void
ndnbootstrapEvent(void* arg, ndn::BootstrapClient::Event evt, uint64_t seq)
{
  int led = reinterpret_cast<int>(arg);
  switch (evt) {
    case ndn::BootstrapClient::Event::BOOTSTRAP_RESPONSE:
      digitalWrite(led, HIGH);
      break;
    case ndn::BootstrapClient::Event::CERTIFICATE_RESPONSE:
      digitalWrite(led, HIGH);
      break;
    case ndn::BootstrapClient::Event::CERTIFICATE_REQUEST:
      digitalWrite(led, HIGH);
      break;
    case ndn::BootstrapClient::Event::BOOTSTRAP_REQUEST:
      digitalWrite(led, HIGH);
      break;    
    //if nothing happens
    default:
      digitalWrite(led, LOW);
      break;
  }
}

void
setup()
{
  Serial.begin(115200);
  Serial.println();
  ndn::setLogOutput(Serial);

  g_transport.begin("ESP32-BLE-NDN");

  g_face.onData(&processData, nullptr);
  g_face.onNack(&processNack, nullptr);

  pinMode(LED0, OUTPUT);

  ndn::parseNameFromUri(g_interest0.getName(), PREFIX0);

  g_client0.onEvent(&ndnbootstrapEvent, reinterpret_cast<void*>(LED0));

}

void
loop()
{
  g_face.loop();
  g_client0.loop();
  delay(10);
}

#endif // ESP32