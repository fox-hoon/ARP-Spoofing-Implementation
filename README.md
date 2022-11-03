# ARP-Spoofing-Implementation
+ **Implement ARP Spoofing tools using JavaFX**
  + 윈도우 환경에서 자바FX를 사용합니다. 자바FX는 이클립스 프로그램에서 추가로 설치하여 사용해야 하고 환경변수를 설정해줘야 합니다. 네트워크에 관련된 부분을 구현하기 위해 jNetPcap라이브러리가 필요하고, jNetPcap라이브러리를 활용하기 위해선 WinPcap을 추가로 설치해줘야 합니다. 패킷에 관련한 정보를 얻기 위해 와이어샤크 프로그램을 사용했습니다. GUI 환경을 구현하는 자바FX를 원활히 사용하기 위해서 인텔 i5프로세서, 램8GB이상의 사양이 필요합니다. ARP 스푸핑 툴을 테스트하기 위해서 노트북 2대와 공유기 역할을 해줄 휴대폰 1대가 필요합니다.
  + ARP 스푸핑 툴을 구현하기 위해 자바MVC(Model, View, Controller) 모델을 적용하였습니다. Model 부분에서는 ARP 헤더와 요청/응답 메소드 및 패킷을 정의하고, View 부분에서는 프로그램의 틀을 구현하기 위해 FXML을 사용하고, Controller 부분에서는 ARP 스푸핑 프로그램의 동작과 제어를 담당하는 Controller 클래스, 프로그램을 실행시키는 Main클래스로 나눠 구현했습니다. 프로그램을 구현하기 위해서 JavaFX라이브러리와 jNetPcap라이브러리를 추가로 적용하였습니다.
  + 구현된 ARP 스푸핑 툴에서 이더넷 어댑터를 선택한 다음에 공격자IP, 피해자IP, 공유기IP를 입력하고 시작버튼을 누르면 공격자 MAC주소가 공유기 MAC주소로 바뀝니다. 그러면 피해자PC에서 패킷을 공유기로 전송하게 되면 공격자PC에서 그 패킷을 가로챕니다. 공격자PC에서는 피해자PC가 전송하는 패킷을 모두 확인할 수 있습니다. 또한, 피해자PC가 정상적으로 네트워크를 사용하는 것처럼 하기 위해서 자바FX에서 구현된 패킷 재전송 클래스가 패킷을 계속해서 재전송 해줍니다. 그러면 피해자PC는 정상적으로 네트워크가 동작한다고 생각합니다. 이 과정을 공격자PC에서 와이어샤크로 확인해보면 피해자PC에서 보낸 패킷들을 확인할 수 있습니다.
***
# Source Code
+ **FXML 소스 코드(프로그램 틀 설계 코드) / View**

![image](https://user-images.githubusercontent.com/84726924/199727906-bc64373e-4565-4d42-8120-f65f4376c5c3.png)
![image](https://user-images.githubusercontent.com/84726924/199728644-d3afda3f-7337-4946-ab7a-ab2979dadd2d.png)
+ **ARP 헤더와 ARP 요청/응답 메소드 구현 / Model**

![image](https://user-images.githubusercontent.com/84726924/199728812-f261a3ed-74e0-47e4-a21b-6ed9994ea135.png)
+ **패킷(바이트형태)을 문자열로 변경해주는 클래스 / Model**

![image](https://user-images.githubusercontent.com/84726924/199728906-39a0875e-074d-4b07-9795-41d44f920490.png)
+ **네트워크 어댑터 출력 / Controller**

![image](https://user-images.githubusercontent.com/84726924/199729188-6233f97b-6f85-4ad0-af03-faab25791ad0.png)
+ **출력된 네트워크 어댑터 선택 / Controller**

![image](https://user-images.githubusercontent.com/84726924/199729313-e6bc3352-2cae-43a4-b5ab-cf68c28a0c31.png)
+ **ARP 요청/응답 코드 / Controller**

![image](https://user-images.githubusercontent.com/84726924/199729374-cbb86bc3-5f32-4217-984c-443c4f25526c.png)
+ **패킷 재전송 클래스 / Controller**

![image](https://user-images.githubusercontent.com/84726924/199729438-56b2a7e5-98cf-4b19-8bdf-c342040f6c10.png)
***
# Test
+ **ARP 스푸핑 공격을 하기 전 피해자PC의 ARP 테이블**

![image](https://user-images.githubusercontent.com/84726924/199729582-fe34f6d2-ce08-416e-aaaa-ac1fa4943dea.png)
+ **사용하는 네트워크 어댑터를 선택한 다음 IP 입력 후 시작 버튼을 클릭하면 아래 사진과 같이 ARP 요청으로 맥 주소를 알아냅니다. 맥 주소를 알아냈으면 ARP 테이블을 감염시키고 계속해서 패킷을 재전송합니다.**

![image](https://user-images.githubusercontent.com/84726924/199729672-35c8dc3d-baa9-49ed-b456-759457bdeb63.png)
+ **ARP 스푸핑 공격을 시작하면 피해자PC의 ARP 테이블이 아래 사진과 같이 출력됩니다. 공격자PC의 MAC주소와 공유기의 MAC주소가 같아집니다. 피해자PC에서 패킷을 공유기로 전송하게 되면 공격자PC에서 모든 패킷을 확인할 수 있습니다.**

![image](https://user-images.githubusercontent.com/84726924/199729728-89124c49-309a-4ffe-9620-e8251992d133.png)
+ **피해자PC에서 네이버 홈페이지로 접속했을 때 공격자PC에서 와이어샤크로 확인해보면 피해자PC가 네이버 홈페이지에 접속했음을 패킷을 통해 확인할 수 있습니다. 추가로 피해자PC에서 보안성이 낮은 웹 사이트에서 로그인을 한다면 입력한 모든 값들을 패킷을 통해 공격자PC가 알아낼 수 있습니다. 이렇게 ARP 스푸핑은 상대방의 데이터 패킷을 중간에서 가로챌 수 있습니다.**

![image](https://user-images.githubusercontent.com/84726924/199729793-cf09fb25-f198-4753-98fc-f361a078a0cb.png)
