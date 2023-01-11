# secure_ftp_program
*Implementations of secure ftp program (MIT License © Yongbhin Kim)*

**[Environment]**
- Language `C` 
- OS `mac`
- Compiler `Apple clang version 13.0.0 (clang-1300.0.29.3)`

**[Compile]**
- Path  `./`
- Command `make`

**[Run]**
- Server
- - Path `./FTP_Server`
- - Command `./server <Port>`
- Client
- - Path `./FTP_Client`
- - Command : `./client <IP> <Port>`
<br>
<br>


<h3/> TCP 기반 FTP 응용 프로그램(서버/클라이언트) 개발</h3>

**[서버(서비스 제공자)]** 
- 서버는 사용자(클라이언트)가 요청한 서비스에 대해서 서비스 처리를 수행한다.

**[클라이언트(사용자)]** 
- 사용자(클라이언트)는 서버로 파일 다운로드/업로드/목록 확인 등의 서비스를 요청한다.
<br>

**[기능]**
- 사용자 등록 기능 제공 (ID/PW 등록) 
- - 사용자 접속 시, ID/PW를 확인하여 일치하는 정보가 있을 경우에만 접속 허용
- - 서버 관리자가 사용자 등록을 할 수 있어야 하며, 등록된 ID/PW를 파일형태로 관리함

- 사용자가 요청 시, 현재 디렉토리의 목록 제공 
- - 사용자가 전송한 “list” 명령어에 대해, 현재 디렉토리 의 목록을 사용자에게 전송

- 사용자가 요청 시, 현재 디렉토리에 있는 파일을 전송
- - 사용자가 전송한 “down” 명령어에 대해, 사용자가 선택한 파일을 사용자에게 전송  
- - `예) down filename1 filename2` 서버의 filename1을 다운받아서 클라이언트에서 filename2로 저장함

- 서버의 현재 디렉토리에 사용자가 파일을 업로드 할 수 있는 기능 제공
- - 사용자가 전송한 “up” 명령어에 대해, 사용자가 선택한 파일을 서버가 전송받아 현재 디렉토리에 저장 
- - `예) up filename1 filename2` 클라이언트의 filename1을 filename2로 서버에 업로드
<br>

**[암호화 통신 고려사항]**
- 클라이언트와 서버가 연결을 설정할 때, 키 설정 방법을 통하여 보안 세션키를 생성해야 함
- - RSAES 기반 키 전송 방법
- ID/PW를 비롯하여 네트워크를 통해 전송되는 모두 데이터는 암호화되어야 함 
- - 블록암호 AES 사용
- - 전송된 암호화된 파일은 목적지에서 복호화된 후 저장되어야 함
- 전송되는 데이터에 대한 무결성도 검증되어야 함
- - gcm모드 사용

**[다중 서버 고려 사항]**
- 서버는 여러 개의 클라이언트에 대해 동시적으로 서비스 할 수 있어야 함
- - 다중 쓰레드

<br>
<br>
