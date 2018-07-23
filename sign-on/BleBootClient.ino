#ifdef ESP32
// extras/BleClient.py is a client that can connect to this ndnping server.

#include <esp8266ndn.h>

char host[] = "/device";
const int LED0 = 15;

ndn::BleServerTransport g_transport;
ndn::Face g_face(g_transport);

//we need construct EcPublicKey and EcPrivateKey here for bootstrap

ndn::BootstrapClient g_client(g_face, /*.......*/);

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

  pinMode(LED0, OUTPUT);

  g_client0.onEvent(&ndnbootstrapEvent, reinterpret_cast<void*>(LED0));

}

void
loop()
{
  g_face.loop();
  if(g_client0.begin()){
    Serial.print("Bootstrap Success");
  }
  delay(10);
}

#endif // ESP32