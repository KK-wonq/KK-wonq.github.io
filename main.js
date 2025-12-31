// 1. [데이터] 포트폴리오 데이터베이스
const portfolioData = [
  // ================= [ Phase 1 : Foundation (기초) ] =================
  {
    id: 'p1_gns3',
    category: 'phase1',
    title: 'GNS3 기본 토폴로지',
    desc: '폐쇄망 환경에서의 기초 보안 네트워크 설계 및 라우팅/스위칭 구축',
    tech: ['GNS3', 'Cisco', 'Network Design'],
    htmlContent: `
      <p>GNS3를 활용하여 가상 환경에서 폐쇄망을 구축했습니다. 외부망과 내부망을 분리하고, 그 사이에 방화벽을 두어 기본적인 보안 아키텍처를 설계했습니다.</p>
      <h3>주요 구성</h3>
      <ul style="list-style: disc; margin-left: 20px; color: #cbd5e1;">
        <li><strong>Router & Switch:</strong> Cisco 장비 VLAN 및 OSPF 라우팅 설정</li>
        <li><strong>Firewall:</strong> 내부망 보호를 위한 ASAv 방화벽 배치</li>
      </ul>
    `,
    images: [
      { src: "port_images/default_GNS3_Topol.PNG", caption: "기본 네트워크 토폴로지" },
      { src: "port_images/ASAv_rules.PNG", caption: "통합 ASAv 방화벽 룰" },
      { src: "port_images/FireFox3_to_inside_http.PNG", caption: "내부망(inside)으로의 HTTP 접속 허용" },
      { src: "port_images/FireFox3_to_inside_telnet.PNG", caption: "내부망(inside)으로의 Telnet 접속 허용" },
      { src: "port_images/PC1_to_webterm1_ping.PNG", caption: "외부망(outside)에서 DMZ로의 ICMP 통신" }
    ]
  },
  {
    id: 'p1_pfsense',
    category: 'phase1',
    title: 'Pfsense 방화벽 구축',
    desc: '오픈소스 방화벽 Pfsense를 활용한 NAT, 정책 설정 및 로드밸런싱',
    tech: ['Pfsense', 'Firewall', 'HAProxy'],
    htmlContent: `
      <p>Pfsense를 구축하여 기업망 수준의 보안 정책을 적용했습니다.</p>
      <p>WAN/LAN/DMZ 인터페이스 분리, 화이트리스트 기반 방화벽 정책 적용, 그리고 HAProxy를 이용한 웹 서버 부하 분산을 구현했습니다.</p>
    `,
    images: [
      { src: "port_images/pfsense_remote_Access.PNG", caption: "Pfsense 연결 중" },
    ]
  },
  {
    id: 'p1_snort',
    category: 'phase1',
    title: 'Snort (NIDS) 탐지 룰',
    desc: 'Snort 구축 및 ICMP, 포트 스캔, DDoS 등 커스텀 탐지 규칙 작성',
    tech: ['Snort', 'NIDS', 'Rule Writing'],
    htmlContent: `
      <h3>사용자 정의 탐지 규칙 (Custom Rules)</h3>
      <p>Snort를 설치하고 직접 룰 파일(local.rules)을 작성하여 다양한 공격을 탐지했습니다.</p>
      <div style="background: rgba(0,0,0,0.3); padding: 15px; border-radius: 8px; margin-top: 10px;">
        <p><strong>1. ICMP & HTTP:</strong> 비정상적인 Ping 및 웹 요청 탐지</p>
        <p><strong>2. Port Scan:</strong> 단시간 내 다수의 접속 시도(Threshold) 탐지</p>
        <p><strong>3. DDoS 시도:</strong> SYN Flooding 공격 패턴 탐지</p>
      </div>
    `,
    images: [
      { src: "port_images/snort_rules_re_re.PNG", caption: "작성한 local.rules 파일" },
      { src: "port_images/snortRule_1.PNG", caption: "HTTP/ICMP 탐지 로그" },
      { src: "port_images/SnortRule_5_Kali.PNG", caption: "SYN 포트 스캔 탐지" },
      { src: "port_images/SnortRule_4.PNG", caption: "DDoS 공격 탐지" }
    ]
  },
  {
    id: 'p1_suricata',
    category: 'phase1',
    title: 'Suricata 고성능 NIDS',
    desc: '멀티스레딩 지원 Suricata 구축 및 대용량 트래픽 처리 테스트',
    tech: ['Suricata', 'NIDS', 'IPS'],
    images: [
      { src: "port_images/suricata_rules_re_re.PNG", caption: "Suricata 작성한 local.rules 파일" },
      { src: "port_images/SuricataRules_5.PNG", caption: "SYN Flag 스캐닝 탐지" },
      { src: "port_images/suricata_rule4.PNG", caption: "URL 명령어 실행 시도 탐지" }
    ]
  },
  {
    id: 'p1_ossec',
    category: 'phase1',
    title: 'OSSEC (HIDS) 구축',
    desc: '서버 내부 무결성 검사(FIM) 및 루트킷 탐지를 위한 OSSEC 구축',
    tech: ['OSSEC', 'HIDS', 'FIM'],
    images: [
      { src: "port_images/OSSEC(HIDS)_ipaddr.PNG", caption: "OSSEC 서버 설정" },
      { src: "port_images/Window10-Ossec.PNG", caption: "윈도우와 연결" }
    ]
  },
  {
    id: 'p1_zabbix',
    category: 'phase1',
    title: 'Zabbix 모니터링',
    desc: 'NMS Zabbix를 이용한 서버/네트워크 리소스 및 트래픽 시각화',
    tech: ['Zabbix', 'NMS', 'SNMP'],
    images: [
      { src: "port_images/Rocky_Zabbix_server.PNG", caption: "Zabbix 대시보드" },
      { src: "port_images/zabbix_link.PNG", caption: "에이전트 연결" }
    ]
  },

  // ================= [ Phase 2 : Integration (통합 및 연동) ] =================
  {
    id: 'p2_topology',
    category: 'phase2',
    title: '통합 보안 아키텍처',
    desc: '방화벽, IDS, DB, 로그 서버가 모두 연동된 Phase 2 통합망 구성',
    tech: ['GNS3', 'Integration', 'Security Arch'],
    htmlContent: `
      <p>개별적으로 구축했던 장비들을 하나의 토폴로지로 통합하여 <strong>다층 방어(Defense in Depth)</strong> 구조를 완성했습니다.</p>
      <p>DMZ에는 웹/DNS, 내부망(Inside)에는 DB/로그 서버를 배치하고 방화벽 정책으로 엄격히 통제했습니다.</p>
    `,
    images: [
      { src: "port_images/images-part/GNS3/topology.png", caption: "Phase 2 통합 토폴로지" },
      { src: "port_images/images-part/GNS3/AsaVrule.png", caption: "통합 방화벽 정책" },
      { src: "port_images/images-part/GNS3/pfrule.png", caption: "pfsense 룰 정책" },
      { src: "port_images/images-part/GNS3/PC7-R3_ping.png", caption: "PC7->inside https 접속" },
      { src: "port_images/images-part/GNS3/DVWA-inside_telnet.png", caption: "PC7->inside telnet 접속" },
      { src: "port_images/images-part/GNS3/R3-rule.png", caption: "라우터 정책 적용" },
      { src: "port_images/images-part/GNS3/R2-Kali_SSH.png", caption: "라우터 정책:R2->Kali SSH 접속" }
    ]
  },
  {
    id: 'p2_dns_db',
    category: 'phase2',
    title: 'DNS & DB 구축',
    desc: '내부망 서비스를 위한 Bind9 DNS 및 MariaDB 데이터베이스 구축',
    tech: ['Bind9', 'MariaDB', 'Linux'],
    images: [
      { src: "port_images/images-part/DNS,LOG,ANAlyzer,DB/DNS_Zone.png", caption: "DNS Zone 설정" },
      { src: "port_images/images-part/DNS,LOG,ANAlyzer,DB/domain-db.png", caption: "DNS 로 데이터베이스가 연동된 페이지 열기" }
    ]
  },
  {
    id: 'p2_log',
    category: 'phase2',
    title: '중앙 로그 분석 시스템',
    desc: 'Wazuh, PMM, LogAnalyzer 로 로그 수집 후 시각화',
    tech: ['Rsyslog', 'LogAnalyzer', 'Centralized Log', 'Wazuh', 'PMM'],
    htmlContent: `
      <p>각 서버(Web, DB, FW)에서 발생하는 Syslog를 중앙 서버로 전송하도록 설정하고, LogAnalyzer 웹 인터페이스를 통해 효율적으로 분석할 수 있는 환경을 구축했습니다.</p>
      <p>Wazuh와 PMM 을 추가 구축하여 에이전트의 로그를 서버로 전송하도록 설정하여 실시간으로 공격을 탐지하였습니다.</p>
    `,
    images: [
      { src: "port_images/images-part/DNS,LOG,ANAlyzer,DB/loganalyzer.png", caption: "LogAnalyzer 분석 화면" },
      { src: "port_images/images-part/wazuh.PNG", caption: "Wazuh 에이전트 연결 후 대시보드 화면" },
      { src: "port_images/images-part/PMM.png", caption: "PMM 에이전트 연결 후 대시보드 화면" }
    ]
  },
  {
    id: 'p2_vpn',
    category: 'phase2',
    title: 'OpenVPN 원격 접속',
    desc: '외부망(Outside)에서 내부망으로 안전하게 접속하기 위한 VPN 터널링',
    tech: ['Pfsense', 'OpenVPN', 'Tunneling'],
    images: [
      { src: "port_images/images-part/VPN/Pfsense.png", caption: "OpenVPN 서버 설정" },
      { src: "port_images/images-part/VPN/access-remote.png", caption: "VPN 연결 성공" }
    ]
  },
  {
    id: 'p2_samba',
    category: 'phase2',
    title: 'Samba 파일 서버',
    desc: 'Windows-Linux 간 파일 공유 및 사용자 권한(ACL) 설정',
    tech: ['Samba', 'File Server', 'ACL'],
    images: [
      { src: "port_images/images-part/Samba,nfs/sambaserver.png", caption: "Samba 설정 후 공유 폴더 접근" }
    ]
  },
  {
    id: 'p2_nfs',
    category: 'phase2',
    title: 'NFS 스토리지 공유',
    desc: 'Linux 서버 간 고속 데이터 공유를 위한 NFS 마운트 설정',
    tech: ['NFS', 'Linux', 'Storage'],
    images: [
      { src: "port_images/images-part/Samba,nfs/nfs-mount.png", caption: "NFS 마운트 확인" },
      { src: "port_images/images-part/Samba,nfs/nfs-server.png", caption: "NFS 서버 확인" }
    ]
  },
  {
    id: 'p2_linux_sec',
    category: 'phase2',
    title: 'Linux 보안 하드닝',
    desc: '서버 계정 관리, SSH 포트 변경, Firewalld 정책 적용',
    tech: ['Linux', 'Hardening', 'SSH'],
    images: [
      { src: "port_images/images-part/Linux/linux4.PNG", caption: "SetUID Bit 를 이용한 권한 상승 실습" },
      { src: "port_images/images-part/Linux/linux-3.png", caption: "로그인 성공/실패 기록 확인1" },
      { src: "port_images/images-part/Linux/linux3-2.PNG", caption: "로그인 성공/실패 기록 확인2" }
    ]
  },
  {
    id: 'p3_venus',
    category: 'phase3',
    title: 'CTF - Vulnhub Venus',
    desc: '포트 스캔, 쿠키 변조, CVE-2021-3156 취약점을 이용한 Root 권한 탈취',
    tech: ['Penetration Test', 'Metasploit', 'Nmap'],
    htmlContent: `
      <h3>1. 환경 분석</h3>
      <p>Nmap 스캔을 통해 22(SSH), 80(HTTP) 포트 오픈 확인.</p>
      <img src="port_images/images-part/ctf/ctf-nmap.png" style="width:100%; border-radius:8px;" alt="Nmap">
      <h3>2. 침투 및 권한 상승</h3>
      <p>SSH 접속 후 User Flag 획득</p>
      <img src="port_images/images-part/ctf/userflag.png" style="width:100%; border-radius:8px;" alt="userflag">
      <p>패킷 캡처로 자격 증명 획득 후, Sudo 취약점(CVE-2021-3156)을 악용하여 Root 획득.</p>
      <img src="port_images/images-part/ctf/CVE.png" style="width:100%; border-radius:8px;" alt="cve">
      <p>root flag 획득</p>
      <img src="port_images/images-part/ctf/rootflag.png" style="width:100%; border-radius:8px;" alt="rootflag">
    `,
    images: [
      { src: "port_images/images-part/ctf/venus.jpg", caption: "Venus" }
    ]
  },

  // ================= [ Phase 3 : Analysis & Hacking (심화) ] =================
  {
    id: 'p3_topology',
    category: 'phase3',
    title: 'GNS3 심화 토폴로지 (Advanced)',
    desc: 'Phase 3를 위한 고도화된 보안 토폴로지 설계 및 구축',
    tech: ['GNS3', 'Advanced Design', 'Integration'],
    // ★ Phase 3 토폴로지 이미지
    images: [
      { src: "part2-image/GNS3/topology.png", caption: "Phase 3 심화 통합 토폴로지" },
      { src: "part2-image/GNS3/AC-ping.png", caption: "Vlan 설정 후 ping 확인" },
      { src: "part2-image/GNS3/asav-rule1.png", caption: "방화벽 룰 작성1" },
      { src: "part2-image/GNS3/rule2.png", caption: "방화벽 룰 작성2" },
      { src: "part2-image/GNS3/rule3.png", caption: "방화벽 룰 작성3" }
    ]
  },
  {
    id: 'p3_wazuh',
    category: 'phase3',
    title: 'SIEM 관제',
    desc: '오픈소스 보안 관제 시스템을 활용한 보안 이벤트 수집 및 대시보드 모니터링',
    tech: ['Wazuh', 'SIEM', 'GoAccess', 'PMM', 'WAF'],
    images: [
      { src: "part2-image/wazuh,go,pmm/nail.png", caption: "통합 로그 분석" },
      { src: "part2-image/wazuh,go,pmm/pmm.png", caption: "PMM 에이전트 등록 연결" },
      { src: "port_images/images-part/wazuh-nail.png", caption: "Wazuh" },
      { src: "part2-image/wazuh,go,pmm/wazuh-1.png", caption: "Wazuh 이벤트 대시보드" },
      { src: "part2-image/wazuh,go,pmm/wazuh-2.png", caption: "Wazuh 에이전트 연결" },
      { src: "part2-image/wazuh,go,pmm/go-nail.png", caption: "WAF(GoAccess)" },
      { src: "part2-image/wazuh,go,pmm/go-1.png", caption: "GoAccess 실시간 터미널 접속" },
      { src: "part2-image/wazuh,go,pmm/go-2.png", caption: "GoAccess 대시보드" },
    ]
  },
  // ★ [통합된 OWASP Juice Shop 카드] ★
  {
    id: 'p3_juice',
    category: 'phase3',
    title: 'OWASP Juice Shop Web Hacking',
    desc: 'OWASP Top 10 취약점 실습 종합 (SQLi, XSS, Logic Flaw)',
    tech: ['Burp Suite', 'Web Hacking', 'OWASP'],
    // ★ 모달 내부에서 '세부 카드 섹션'처럼 보이도록 HTML 구성
    htmlContent: `
      <h3>OWASP Top 10 취약점 공격 실습</h3>
      <p>대표적인 취약한 웹 애플리케이션인 Juice Shop을 대상으로 다양한 웹 해킹 기법을 실습했습니다.</p>
      
      <div style="background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; padding: 20px; margin-top: 20px;">
        <h4 style="color: #22d3ee; margin-top: 0;">1. SQL Injection (Login Admin)</h4>
        <p>로그인 폼에 <code>' OR 1=1 --</code> 구문을 삽입하여 관리자 계정으로 우회 로그인에 성공했습니다.</p>
        <img src="part2-image/Juicy/login-admin/1-2.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="SQLi">
        <img src="part2-image/Juicy/login-admin/1-3.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="SQLi">
      </div>

      <div style="background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; padding: 20px; margin-top: 20px;">
        <h4 style="color: #f472b6; margin-top: 0;">2. DOM XSS</h4>
        <p>검색창(Search)에 스크립트 태그를 삽입하여 사용자 브라우저에서 임의의 코드가 실행되도록 했습니다.</p>
        <img src="part2-image/Juicy/dom/7-2.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="XSS">
        <p>검색창에 삽입한 스크립트가 그대로 실행되는 것을 확인할 수 있었습니다.</p>
        <img src="part2-image/Juicy/dom/7-3.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="XSS">
      </div>

      <div style="background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; padding: 20px; margin-top: 20px;">
        <h4 style="color: #a855f7; margin-top: 0;">3. Kill Chatbot (Logic Flaw)</h4>
        <p>챗봇 소스 코드를 분석하여 특정 로직의 취약점을 이용해 챗봇 서비스를 비활성화시켰습니다.</p>
        <img src="part2-image/Juicy/kill/9-2.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="Chatbot">
        <img src="part2-image/Juicy/kill/9-3.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="Chatbot">
        <p>알려진 취약점이 있는 구성요소 사용. 관련문제입니다. 고객문의에 사용되는 챗봇을 영구적으로 비활성해야 합니다. 먼저 구글에 juicy-chat-bot 을 치면 깃허브 사이트가 나옵니다.
https://github.com/juice-shop/juicy-chat-bot/blob/master 이 사이트로 가면 챗봇의 js파일을 확인할 수 있습니다.</p>
        <img src="part2-image/Juicy/kill/9-5.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="Chatbot">
        <p>만약 admin"); process=null; users.addUser("1337", "test" 라고 말을 적어 보내면 챗봇은 admin 토큰, process=null; 로 처리하고, test 유저까지 저장됩니다. 그렇게 시스템을 꼬이게 만들고 process 까지 null로 만들면 시스템은 비활성화 됩니다.</p>
      </div>
    `,
    images: [
      { src: "part2-image/Juicy/juicy-nail.png", caption: "Juice Shop" },
      { src: "part2-image/Juicy/login-admin/1-1.png", caption: "SQL Injection" },
      { src: "part2-image/Juicy/dom/7-1.png", caption: "DOM XSS" },
      { src: "part2-image/Juicy/kill/9-1.png", caption: "Kill Chatbot" }
    ]
  },
  {
    id: 'p3_bluemoon',
    category: 'phase3',
    title: 'CTF - Bluemoon Docker',
    desc: 'FTP 취약점 공략 및 Docker Container Escape 기법 연구',
    tech: ['Docker Escape', 'FTP Exploit', 'Linux'],
    htmlContent: `
      <h3>1. 환경 분석 및 취약점 확인</h3>
      <p>Ip 확인 후 namp 스캐닝. 21(ftp),22(ssh),80(http) 번호가 열려있음을 확인했습니다.</p>
      <img src="part2-image/ctf/3.png" style="width:100%; border-radius:8px;" alt="Nmap">
      <p>취약점을 분석하여 username 을 찾아내고, 비밀번호 리스트를 통해 ssh 접속 패스워드를 알아내었습니다.</p>
      <img src="part2-image/ctf/12.png" style="width:100%; border-radius:8px;" alt="hydra">
      <img src="part2-image/ctf/13.png" style="width:100%; border-radius:8px;" alt="ssh">

      <h3>2. 플래그 획득</h3>
      <p>유저 플래그를 획득합니다.</p>
      <img src="part2-image/ctf/14.png" style="width:100%; border-radius:8px;" alt="userflag">
      <p>취약점이 있는 실행파일과 docker alpine 을 이용해 root flag 까지 획득합니다.</p>
      <img src="part2-image/ctf/20.png" style="width:100%; border-radius:8px;" alt="rootflag">
    `,
    images: [
      { src: "part2-image/ctf/bluemoon.png", caption: "Bluemoon 풀이과정" }
    ]
  },
  {
    id: 'p3_malware',
    category: 'phase3',
    title: '악성코드 분석 (Mimikatz)',
    desc: 'Flare-VM 환경에서의 Mimikatz SSP 인젝션 기법 상세 리버싱',
    tech: ['Reverse Engineering', 'IDA Pro', 'x64dbg'],
    htmlContent: `
      <h3>1. 사용한 샘플 악성코드에 대하여</h3>
          <p>보안 지원 공급자(SSP)로 위장하여 시스템에 등록되는 것이 목적인 악성 코드입니다.</p>
          <p>SSP는 윈도우 로그인을 처리할 때 LSA라는 프로세스를 사용하는데, 이 LSA에 연결되어 인증작업을 돕는 합법적인 DLL입니다.</p>
          <p>mimilib.dll 이 등록되면 이후 해당 시스템에서 로그인을 시도하는 모든 사용자의 비밀번호가 평문 그대로 이 DLL에 의해 가로채집니다. 비밀번호를 mimisa.log(예시) 같은 파일에 저장합니다.</p>

          <p></p>
          <br>

          <h3>2. PEsutido  탐색 결과</h3>
          <img src="part2-image/flare-vm/1.png" style="width:100%; border-radius:8px;" alt="1">
          <p>SpLsaModeInitialize 함수로 mimilib.dll 을 SSP로 등록합니다. LSA가 시작될 때 이 함수를 호출하며, 이때부터 mimilib.dll 은 시스템에 로그인하는 모든 계정의 암호를 가로챌 준비를 하는 겁니다.</p>
          <p>PasswordChangeNotify / NPLogonNotify 함수는 이름 그대로 <strong>비밀번호 변경</strong> 또는 <strong>네트워크 로그온</strong>이벤트가 발생할 때 마다 Windos가 이 함수들을 호출해줍니다. Mimikatz는 이 알림을 받아서 변경된 새 비밀번호, 로그온 정보를 즉시 훔치게 되는 겁니다.</p>
          <p>DnsPluginInitialize / DncpNewPktHook 함수는 LSA뿐만 아니라 DNS서버나 DHCP 서버 서비스에도 플러그인으로 작동할 수 있음을 의미합니다. 네트워크 요청이나 IP주소 할당 과정에도 개입할 수 있습니다.</p>

          <p></p>
          <br>

          <h3>3. IDA로 SpLsaModeInitialize 추적</h3>
          <img src="part2-image/flare-vm/2.png" style="width:100%; border-radius:8px;" alt=2>
          <p>먼저 SSP로 등록하는 함수가 export 되는 것을 볼 수 있습니다.</p>
          <img src="part2-image/flare-vm/3.png" style="width:100%; border-radius:8px;" alt=3>
          <p>보안 설정 쿠키를 가져오는 것을 확인할 수 있습니다. 여기로 들어가보겠습니다.</p>
          <img src="part2-image/flare-vm/4.png" style="width:100%; border-radius:8px;" alt=4>
          <p>각종 System 파일의 id 등을 가져옴.</p>

          <p></p>
          <br>

          <h3>4. 비밀번호를 가로채서 log 파일에 숨겨적는 함수를 추적함.</h3>
          <img src="part2-image/flare-vm/5.png" style="width:100%; border-radius:8px;" alt=5>
          <p>GetProcAddress 로 몰래 주소를 찾아와서 사용하는 악성 함수입니다. 이 위에 있는 함수를 찾아보면,</p>
          <img src="part2-image/flare-vm/6.png" style="width:100%; border-radius:8px;" alt=6>
          <p>LoadLibraryW 라는 함수를 호출하여 비밀번호가 어디에 있는지 찾아가는 중임을 알 수 있습니다.</p>
          <img src="part2-image/flare-vm/7.png" style="width:100%; border-radius:8px;" alt=7>
          <p>해당 함수를 컴파일 해본 결과, 윈도우 자격증명과 고급 API가 들어있는 핵심 DLL 두개를 메모리로 불러옵니다. 그 후 GetProcAddress(v7, "CredIsProctectedW")... advapi32.dll 라이브러리 안에서 암호화되었는지 확인하고 암호화를 해제하는 함수의 실제 주소를 찾아갑니다.</p>
          <p>그 다음 자격 증명 관리자에서 암호화 후 CredProtectW 에 저장합니다.</p>

          <p></p>
          <br>

          <h3>5. 저장한 암호화 방법 및 자격 증명 암호를 어디에 저장하는지 추적</h3>
          <img src="part2-image/flare-vm/8.png" style="width:100%; border-radius:8px;" alt=8>
          <p>이전 단계에서 찾아온 함수들로 암호화된 비밀번호를 log 파일에다가 저장하는 알고리즘을 찾았습니다. 만약 v18 이라는 자격증명이 암호화되지 않았다면 혹은 암호해제에 성공했다면 log 파일을 쓰기모드로 열어서 방금 연 파일에 sub_180004V30 함수를 엽니다.</p>
          <p><b>Sub-180004B30 함수</b> 를 열어보면</p>
          <img src="part2-image/flare-vm/9.png" style="width:100%; border-radius:8px;" alt=9>
          <p>Vfwprintf 로 log 파일에 글씨를 씁니다. Stream 은 아까의 log 파일을 불러오는 것이고, a2,va 는 훔친 비밀번호 암호화 해제 후 평문이 들어가있는 데이터를 뜻합니다. 그것을 log 파일에 작성하고 fflush 명령어로 저장하라는 뜻입니다.</p>

          <p></p>
          <br>

          <h3>6. 짧은 동적 분석</h3>
          <img src="part2-image/flare-vm/10.png" style="width:100%; border-radius:8px;" alt=10>
          <img src="part2-image/flare-vm/11.png" style="width:100%; border-radius:8px;" alt=11>
          <p>cmd 로 rundll32.exe 를 통해 실행시킨뒤 process Monitor 에서 rundll32.exe 캡처해보았습니다.</p>
          <p>필터 로그라는게 새로 생긴 것을 알 수 있습니다. 비밀번호를 변경하는 활동은 하지 않았기 때문에 로그에 무언가 적히지는 않았습니다.</p>

          <br>
    `,
    images: [
      { src: "part2-image/flare-vm/flare_nail.png", caption: "악성 코드 MimiKatz-mimilib.dll 분석" }
    ]
  },
  // ================= [ Phase 4 : Team Project (팀 프로젝트) ] =================
  {
    id: 'p4_ctf_web',
    category: 'phase4',
    title: 'CTF Team Project - Web Hacking',
    desc: '팀 프로젝트: CTF 를 제작하여 웹사이트로 취약점을 분석하여 Root 권한 탈취',
    tech: ['SQLmap', 'Fuzzing', 'Gobuster', 'Blind Injection'],
    // ★ 다운로드할 파일 목록 추가
    
    downloadDesc:'버튼을 클릭하여 CTF 전체 워크스루 보고서(PDF)파일과 가상머신 CTF OVA 파일을 다운받을 수 있습니다.',
    downloads: [
      { name: 'Full Walkthrough (PDF)', src: 'part3-image/ctf/팀_프로젝트_풀이과정(CTF).pdf' },
      { name: 'Project VM (OVA)', src: 'https://drive.google.com/file/d/1qPtaBbjD_TA1BNAV04lhG9ebSwV3HZdq/view?usp=drive_link' }       // 실제 파일 경로로 수정 필요
    ],
    htmlContent: `
      <h2>로그인 페이지 SQL Injection</h2>
      <p>CTF를 제작하는 팀프로젝트에서 <code>로그인 페이지</code>에 취약점을 넣는 부분을 맡았습니다.</p>
      
      <p></p>
      <br>
        
      <h3>1. 환경 분석</h3>
      <p>먼저 로그인 페이지에 로그인을 하기 위해 회원가입을 진행합니다.</p>
      <img src="part3-image/ctf/ctf-2.png" style="width:100%; border-radius:8px;" alt=10>
      
      <p>회원가입 후 들어가보면 admin만 접근가능한 업로드 장소로 가는 버튼이 있습니다.</p>
      <img src="part3-image/ctf/ctf-3.png" style="width:100%; border-radius:8px;" alt=10>
      <p>디렉터리 바로 아래에 <code>gobuster</code>를 이용해서 추가적인 파일을 확인해봅니다.</p>
      <img src="part3-image/ctf/ctf-4.png" style="width:100%; border-radius:8px;" alt=10>
      <p>가장 의심스러운 파일은 search.php 파일이라고 생각할 수 있습니다.</p>

      <p></p>
      <br>
      
      <h3>2. SQL Injection</h3>
      <p>search.php 파일에 들어가보면 ERROR 라는 문구만 뜨는 것을 볼 수 있습니다. 하지만 반응을 한다는 것은 확인할 수 있습니다.</p>
      <img src="part3-image/ctf/ctf-5.png" style="width:100%; border-radius:8px;" alt=10>
      <p>경로에 아무 파라미터나 집어넣어서 들어가봐도 오류는 뜨지 않았습니다.</p>
      <img src="part3-image/ctf/ctf-6.png" style="width:100%; border-radius:8px;" alt=10>
      <p>퍼징으로 파라미터를 찾아보게 되면은, 굉장히 많은 파라미터값이 매칭되는 것을 볼 수 있습니다. 이것을 특정 조건을 붙여 제외시켜볼 수 있습니다.</p>
      <img src="part3-image/ctf/ctf-7.png" style="width:100%; border-radius:8px;" alt=10>
      <img src="part3-image/ctf/ctf-8.png" style="width:100%; border-radius:8px;" alt=10>
      <p>그렇게 되면 파라미터 값은 q로 나오게 되고, URI 에 넣어서 다시 들어가보면, 이번에는 다른 글자가 적히는 것을 확인할 수 있습니다.</p>
      <img src="part3-image/ctf/ctf-11.png" style="width:100%; border-radius:8px;" alt=10>
      <p>힌트로 블라인드 인젝션이라는 것을 알 수 있습니다.</p>

      <p></p>
      <br>

      <h3>3. SQLMAP</h3>
      <p><code>SQL MAP</code>을 통해 데이터베이스를 알아보겠습니다.</p>
      <img src="part3-image/ctf/ctf-12.png" style="width:100%; border-radius:8px;" alt=10>
      <p>데이터베이스 중 website 라는 데이터베이스를 발견했습니다. --dump 옵션을 추가하여 모든 데이터를 확인해볼 수 있습니다.</p>
      <img src="part3-image/ctf/ctf-13.png" style="width:100%; border-radius:8px;" alt=10>
      <p>이렇게 admin 계정의 패스워드를 찾을 수 있었습니다. 이걸로 로그인페이지에서 admin으로 로그인할 수 있습니다.</p>
      <img src="part3-image/ctf/ctf-14.png" style="width:100%; border-radius:8px;" alt=10>
      
    `,
    images: [
      { src: "part3-image/ctf/ctf-1.png", caption: "CTF 첫 화면" },
    ]
  },
  // ================= [ Phase 4 : Wargame (개인 연구) ] =================
  {
    id: 'p3_wargame_pw1234',
    category: 'phase4',
    title: 'Wargame: Password1234',
    desc: '웹 해킹부터 루트 권한 획득까지: 단계별(Easy~Hard) 시스템 침투 실습 워크스루',
    tech: ['Web Hacking', 'SQL Injection', 'Session Hijacking', 'Privilege Escalation'],
    
    downloadDesc: '아래 버튼을 클릭하여 전체 Wargame 워크스루 보고서(PDF)와 Wargame OVA 파일을 다운로드 받을 수 있습니다.',
    downloads: [
      { 
        name: 'Wargame Walkthrough (PDF)', 
        src: 'part3-image/wargame/password1234-wargame_워크스루.pdf' 
      },
      { 
        name: 'Wargame VM (OVA)', 
        src: 'https://drive.google.com/file/d/1bsjcZof9CqIn9axXwGMUNPnVSR1yyLIC/view?usp=drive_link' 
      }
    ],

    htmlContent: `
      <h3>제가 맡은 팀프로젝트 Wargame 문제의 풀이과정입니다.</h3>
      <p>가상의 취약한 서버(Password1234)를 대상으로 정보 수집, 웹 취약점 공략, 쉘 획득, 그리고 권한 상승 등의 문제를 다루었습니다.</p>
      
      <div style="background: rgba(255,255,255,0.05); border-left: 4px solid #22d3ee; border-radius: 4px; padding: 20px; margin-top: 25px;">
        <h4 style="color: #22d3ee; margin-top: 0; display:flex; justify-content:space-between;">
          <span>1. SystemHacking - SSH 원격접속</span>
          <span style="font-size:0.8em; opacity:0.7; border:1px solid #22d3ee; padding:2px 8px; border-radius:12px;">Level: Easy 2</span>
        </h4>
        <p><strong>목표:</strong> SSH 접속 후 플래그를 획득하기</p>
        <p>먼저 주어진 SSH 원격접속 username 과 패스워드로 접속합니다.</p>
        <img src="part3-image/wargame/s2-1.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="easy2">
        <p>그 다음 sudo -l 명령어로 실행시킬 수 있는 파일이 있는지 확인합니다. 확인해보니 playssh2 라는 사용자의 권한으로 ssh 원격 접속 키파일인 id_rsa 파일을 cat 으로 볼 수 있습니다.</p>
        <img src="part3-image/wargame/s2-2.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="easy2">
        <p>playssh2 사용자의 권한으로 파일을 확인하여 원격접속 키내용을 복사해서 파일을 만듭니다.</p>
        <img src="part3-image/wargame/s2-3.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="easy2">
        <p>만든 파일로 옵션을 이용해 playssh2 사용자로 원격접속을 시도해봅니다.</p>
        <p>하지만 원격접속을 시도해도 코멘트가 없다는 말과 함께 Connection closed 된 것을 확인할 수 있었습니다.</p>
        <img src="part3-image/wargame/s2-4.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="easy2">
        <p>뒤에 명령어를 추가하여 다시 원격접속을 시도하니, 이번에는 해당 명령어의 출력결과가 나오는 것을 확인할 수 있습니다.</p>
        <img src="part3-image/wargame/s2-5.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="easy2">
        <p>이대로 flag.txt 파일을 보는 명령어를 집어넣어 flag 값을 획득할 수 있었습니다.</p>
        <img src="part3-image/wargame/s2-6.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="easy2">
      </div>

      <div style="background: rgba(255,255,255,0.05); border-left: 4px solid #a855f7; border-radius: 4px; padding: 20px; margin-top: 25px;">
        <h4 style="color: #a855f7; margin-top: 0; display:flex; justify-content:space-between;">
          <span>Step 2. WebHacking - Drag</span>
          <span style="font-size:0.8em; opacity:0.7; border:1px solid #a855f7; padding:2px 8px; border-radius:12px;">Level: Noob 2</span>
        </h4>
        <p><strong>목표:</strong> Flag 획득</p>
        <p>들어가자마자 보이는 화면의 글자에 드래그를 해볼 수 있습니다.</p>
        <img src="part3-image/wargame/wn-1.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="noob2">
        <p>곧바로 플래그 값을 획득할 수 있었습니다.</p>
      </div>

      <div style="background: rgba(255,255,255,0.05); border-left: 4px solid #f472b6; border-radius: 4px; padding: 20px; margin-top: 25px;">
        <h4 style="color: #f472b6; margin-top: 0; display:flex; justify-content:space-between;">
          <span>Step 3. WebHacking - SQLi</span>
          <span style="font-size:0.8em; opacity:0.7; border:1px solid #f472b6; padding:2px 8px; border-radius:12px;">Level: Normal 2</span>
        </h4>
        <p><strong>목표:</strong> SQL injection 에 성공하고 플래그 값 획득</p>
        <p>문제에 진입하면 검색창 화면이 나타납니다. 이 부분에 ' 라는 문자를 삽입하고 검색버튼을 누를 수 있습니다.</p>
        <img src="part3-image/wargame/wnor-1.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="normal2">
        <p>그렇게 되면 fatal 에러가 화면에 뜨게됩니다. 이것으로 injection 이 가능한 페이지라는 것을 확인할 수 있습니다.</p>
        <img src="part3-image/wargame/wnor-2.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="normal2">
        <p>검색창에 이번에는 참이 되는 구문(' or 1=1#)을 집어넣으니 담겨진 모든 내용이 뜨는 것을 확인할 수는 있지만, 플래그는 뜨지 않습니다.</p>
        <img src="part3-image/wargame/wnor-3.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="normal2">
        <p>UNION 구문을 이용해서 다른 칼럼에 있는 내용들을 모조리 긁어내볼 수 있습니다.</p>
        <img src="part3-image/wargame/wnor-4.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="normal2">
        <p>password 라는 컬럼을 검색하니 플래그가 적혀진 것을 확인할 수 있었습니다.</p>
        <img src="part3-image/wargame/wnor-5.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="normal2">
      </div>

      <div style="background: rgba(255,255,255,0.05); border-left: 4px solid #fb923c; border-radius: 4px; padding: 20px; margin-top: 25px;">
        <h4 style="color: #fb923c; margin-top: 0; display:flex; justify-content:space-between;">
          <span>Step 4. WebHacking - Seesion Hijacking</span>
          <span style="font-size:0.8em; opacity:0.7; border:1px solid #fb923c; padding:2px 8px; border-radius:12px;">Level: Hard 2</span>
        </h4>
        <p><strong>목표:</strong> 세션을 탈취하여 Admin으로 로그인하기</p>
        <p>문제로 들어가게 되면 로그인 페이지가 나옵니다. 평범하게 회원가입 후 로그인을 하게 되면 mypage 창이 나옵니다..</p>
        <img src="part3-image/wargame/wh-1.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="hard2">
        <p>Gobuster 도구를 이용해 해당 경로 밑에 무엇이 더 있는지 확인해볼 수 있습니다.</p>
        <img src="part3-image/wargame/wh-2.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="hard2">
        <p>확인한 파일들 중, Bot.php 로 들어가게 되면, 짧은 글하나가 적혀있습니다.</p>
        <img src="part3-image/wargame/wh-3.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="hard2">
        <p>해당 php 의 페이지소스를 보면 <code>아마 봇은 쿠키 로그파일을 적고있을 것이다.</code> 라는 힌트가 적혀있는 것으로, 봇은 지속적으로 어떤 파일에 로그 파일을 적고있고, 그것이 여기 폴더에 텍스트 파일로 있다는 것을 알 수 있습니다.</p>
        <img src="part3-image/wargame/wh-4.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="hard2">
        <p>그 텍스트 파일이 cookie_log.txt 라는 이름으로 있다는 것을 확인했고, 그 파일의 내용을 확인해보면 sessionid 값이 있는 것을 확인할 수 있습니다.</p>
        <img src="part3-image/wargame/wh-5.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="hard2">
        <p>개발자 도구로 들어가 세션 아이디의 value 부분에 방금 복사한 id 값을 넣습니다.</p>
        <img src="part3-image/wargame/wh-6.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="hard2">
        <p>그런 다음 mypage 창으로 다시 이동하게되면, admin 으로 로그인하면서 플래그값을 획득하게 됩니다.</p>
        <img src="part3-image/wargame/wh-7.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="hard2">
      </div>

      <div style="background: rgba(255,255,255,0.05); border-left: 4px solid #ef4444; border-radius: 4px; padding: 20px; margin-top: 25px;">
        <h4 style="color: #ef4444; margin-top: 0; display:flex; justify-content:space-between;">
          <span>Step 5. WebHacking - Network Diagnosis Tool</span>
          <span style="font-size:0.8em; opacity:0.7; border:1px solid #ef4444; padding:2px 8px; border-radius:12px;">Level: Very Hard</span>
        </h4>
        <p><strong>목표:</strong> Flag 값을 조합해내고 최종 플래그 값 획득</p>
        <p>해당 문제는 네트워크 진단 도구를 이용한 문제입니다.</p>
        <p>문제에 들어가게 되면 진단할 IP 주소를 입력할 수 있습니다. 여기에 아무 주소나 넣고 핑테스트 버튼을 누르면 진단결과가 뜨는 것을 확인할 수 있습니다.</p>
        <p>sleep 명령어를 이용해 if 문으로 참 거짓을 판별하여 플래그 값을 찾을 수 있습니다.</p>
        <img src="part3-image/wargame/wvh-1.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="very hard 1">
        <p>페이지 소스를 확인해보면, flag 텍스트파일의 위치를 알 수 있습니다.</p>
        <img src="part3-image/wargame/wvh-2.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="very hard 2">
        <p>cat 으로 sleep 5 를 걸어서 맞다면 5초뒤 진단결과 텍스트가 뜨고, 아니라면 딜레이없이 바로 진단결과 메시지가 나오는 것을 확인할 수 있습니다.</p>
        <p>이것으로 첫번째 글자부터 끝까지 찾을 수 있습니다.</p>
        <p><code>8.8.8.8; cat /opt/ping_flag.txt | cut -c 1 | grep -x "F" && sleep 5</code> 라는 코드를 보내보면, 5초의 딜레이 후 진단결과 텍스트가 나타나는 것을 확인해볼 수 있습니다.</p>
        <img src="part3-image/wargame/wvh-3.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="very hard 3">
        <p>이러한 작업을 반복하여 FLAG 값을 확인할 수 있습니다.</p>
      </div>
    `,
    images: [
      { src: "part3-image/wargame/password1234-wargame.PNG", caption: "Password1234 Wargame 메인" },
      { src: "part3-image/wargame/seasy2.png", caption: "SystemHacking - easy2" },
      { src: "part3-image/wargame/wnoob2.png", caption: "WebHacking - noob2" },
      { src: "part3-image/wargame/wnormal2.png", caption: "WebHacking - normal2" },
      { src: "part3-image/wargame/whard2.png", caption: "WebHacking - hard2 " },
      { src: "part3-image/wargame/wveryhard1.png", caption: "WebHacking - Very hard1" }
    ]
  },
  {
    id: 'p4_team_jangbogo',
    category: 'phase4',
    title: '가상 커머스 "장보고마켓" 보안 구축 및 대응',
    desc: '팀 프로젝트: 전자상거래 서비스 풀스택 구축부터 취약점 진단, WAF 차단 및 Splunk 보안 관제 시스템 구축',
    tech: ['WAF', 'ModSecurity', 'Splunk', 'Docker', 'SIEM', 'Team Project'],
    downloadDesc: '아래 버튼을 클릭하여 팀프로젝트 전체 결과 보고서, 구현한 웹 및 모바일 취약점 정리 보고서, 취약점 공격 및 탐지 보고서 파일을 다운로드 받을 수 있습니다.',
    downloads: [
      { 
        name: '보안 취약점 정리(웹 및 모바일) 보고서 (PDF)', 
        src: 'part3-image/hack/document/보안_취약점_정리(웹&모바일).pdf' 
      },
      { 
        name: '웹&모바일 취약점 공격 및 탐지 결과 보고서 (PDF)', 
        src: 'part3-image/hack/document/웹_취약점_공격_및_탐지.pdf' 
      },
      { 
        name: 'Splunk 구축 보고서 (PDF)', 
        src: 'part3-image/hack/document/Splunk_로그_구축_이야기.pdf' 
      },
      { 
        name: '팀프로젝트 모의해킹 프로젝트 전체 보고서 (PDF)', 
        src: 'part3-image/hack/document/팀패스워드_모의해킹_보고서.pdf' 
      },
      
    ],
    htmlContent: `
      <h2>1. 프로젝트 개요</h2>
      <p>가상 전자상거래 서비스 "장보고마켓"을 직접 구축하고, 실제 공격 시나리오를 기반으로 취약점을 진단 및 방어하는 프로젝트를 수행했습니다.</p>
      <img src="port_images/team_project/hacking_2.png" style="width:100%; border-radius:8px; margin-top:10px;" alt="프로젝트 개요">

      <h3 style="margin-top: 30px;">맡은 역할과 활동</h3>
      <div style="background: rgba(255,255,255,0.05); padding: 15px; border-radius: 8px;">
        <ul style="list-style: none; padding-left: 0; color: #cbd5e1;">
          <li style="margin-bottom: 8px;"><strong>👑 팀장 이혜원:</strong> 전체 일정 관리, Frontend/Backend 구현, WAF 및 Splunk 구축</li>
        </ul>
      </div>
      <img src="part3-image/hack/hacking_1.png" style="width:100%; border-radius:8px; margin-top:10px;" alt="팀원 소개">

      <hr style="border-color: rgba(255,255,255,0.1); margin: 30px 0;">

      <h2>2. 대상 시스템 구성 (Architecture)</h2>
      <p>외부망(Web/Mobile)에서 방화벽, WAF, IDS/IPS를 거쳐 내부망(Web/DB)으로 접근하는 3계층 보안 아키텍처를 설계했습니다. 또한 별도의 보안 관제망을 두어 ELK Stack과 Wazuh로 로그를 중앙 집중화했습니다.</p>
      <img src="part3_image/hack/hacking_3.jpg" style="width:100%; border-radius:8px; margin-top:10px;" alt="시스템 구성도">

      <hr style="border-color: rgba(255,255,255,0.1); margin: 30px 0;">

      <h2>3. 주요 취약점 분석 및 대응: CSRF</h2>
      <p>프로젝트 중 식별된 주요 취약점 중 하나인 <strong>CSRF(Cross Site Request Forgery)</strong> 공격과 이를 보안 장비(WAF)로 방어한 사례입니다.</p>

      <div style="background: rgba(255,255,255,0.05); border-left: 4px solid #ef4444; border-radius: 4px; padding: 20px; margin-top: 20px;">
        <h4 style="color: #ef4444; margin-top: 0;">Step 1. 공격 시나리오 (Attack)</h4>
        <p>공격자는 관리자나 일반 사용자가 의도치 않게 상품 정보를 수정하거나 등록하도록 유도하는 악성 폼(Form) 페이지를 작성했습니다.</p>
        <p>아래 코드는 <code>document.attackForm.submit()</code> 자바스크립트를 이용해 페이지 로드 즉시 POST 요청을 보내는 공격 코드입니다.</p>
        <img src="part3_images/hack/csrf1.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="CSRF 공격 코드">
      </div>

      <div style="background: rgba(255,255,255,0.05); border-left: 4px solid #22d3ee; border-radius: 4px; padding: 20px; margin-top: 20px;">
        <h4 style="color: #22d3ee; margin-top: 0;">Step 2. 보안 대응 및 결과 (Defense)</h4>
        
        <p><strong>1. ModSecurity 보안 룰 설정 (Whitelist)</strong></p>
        <p>CSRF 공격을 방어하기 위해 <code>Referer</code>와 <code>Origin</code> 헤더를 검증하는 커스텀 룰을 적용했습니다.</p>
        <img src="part3-image/hack/csrf-waf.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="WAF 룰 설정">
        <ul style="color: #cbd5e1; font-size: 0.9em; margin-top: 10px; margin-bottom: 20px;">
             <li><strong>Rule 10051~10052:</strong> 신뢰할 수 있는 도메인(jangbogo.com 등)인 경우 검증을 통과(Pass)시킵니다.</li>
             <li><strong>Rule 10053:</strong> 위 검증을 통과하지 못한 상태에서 데이터 변경 요청(POST 등)이 들어오면 <strong>403 Forbidden</strong>으로 차단합니다.</li>
        </ul>

        <p><strong>2. 차단 결과 확인</strong></p>
        <p>공격 스크립트가 실행되었을 때, WAF가 비정상적인 요청(Origin/Referer 불일치)을 감지하고 차단했습니다.</p>
        
        <p style="margin-top:15px; font-weight:bold; color:#cbd5e1;">[WAF 차단 로그]</p>
        <p>로그에서 <code>Pattern match "CSRF Attack Detected"</code> 메시지와 함께 403 Forbidden 코드로 접근이 거부된 것을 확인할 수 있습니다.</p>
        <img src="part3-image/hack/csrf3.png" style="width:100%; border-radius:6px; margin-top:5px;" alt="WAF 로그">

        <p style="margin-top:15px; font-weight:bold; color:#cbd5e1;">[차단 화면]</p>
        <img src="part3_image/hack/csrf2.png" style="width:100%; border-radius:6px; margin-top:5px;" alt="403 Forbidden">
      </div>

      <hr style="border-color: rgba(255,255,255,0.1); margin: 40px 0;">

      <h2>4. 통합 보안 관제 시스템 구축 (Splunk)</h2>
      <p>단편적인 로그 확인의 한계를 극복하기 위해 <strong>Docker 기반의 Splunk 환경</strong>을 구축하고, 실시간 위협 탐지 대시보드를 구현했습니다.</p>

      <div style="background: rgba(255,255,255,0.05); border-left: 4px solid #22c55e; border-radius: 4px; padding: 20px; margin-top: 20px;">
        <h4 style="color: #22c55e; margin-top: 0;">Step 1. 환경 구축 및 로그 연동</h4>
        <p>Ubuntu 서버에 Docker 컨테이너로 Splunk Enterprise를 설치하고, 웹 서버(Rocky Linux)에는 Universal Forwarder를 설치하여 로그 수집 체계를 구성했습니다.</p>
        
        <ul style="color: #cbd5e1; font-size: 0.9em; margin-top: 10px;">
             <li><strong>설치:</strong> RPM 패키지를 이용한 Splunk Forwarder 설치 (Linux)</li>
             <li><strong>연동:</strong> <code>./splunk add monitor</code> 명령어로 WAF 로그(modsec_audit.log)를 실시간 포워딩</li>
        </ul>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 10px;">
            <img src="part3-image/hack/splunk2.png" style="width:100%; border-radius:6px;" alt="Splunk 설치">
            <img src="part3-image/hack/splunk3.png" style="width:100%; border-radius:6px;" alt="로그 모니터링 추가">
        </div>
      </div>

      <div style="background: rgba(255,255,255,0.05); border-left: 4px solid #22c55e; border-radius: 4px; padding: 20px; margin-top: 20px;">
        <h4 style="color: #22c55e; margin-top: 0;">Step 2. 위협 데이터 분석 및 시각화</h4>
        <p>수집된 WAF 로그를 정규표현식(Rex)으로 필드 파싱하여 <strong>공격 유형별 통계</strong>를 시각화했습니다.</p>
        
        <p style="margin-top:15px; font-weight:bold; color:#cbd5e1;">[탐지된 주요 공격]</p>
        <p>Splunk 검색어(SPL)를 이용해 <code>CSRF Attack</code>, <code>XSS Attack</code> 등의 키워드를 추출하여 통계 테이블을 생성했습니다.</p>
        <img src="part3-image/hack/splunk5.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="공격 탐지 통계">
      </div>
    `,
    images: [
      { src: "part3-image/hack/hacking_1.png", caption: "팀원 역할 소개" },
      { src: "part3-image/hack/hacking_2.png", caption: "프로젝트 개요" },
      { src: "part3_image/hack/hacking_3.jpg", caption: "시스템 아키텍처" },
      { src: "part3-image/hack/csrf-waf.png", caption: "WAF 보안 정책 설정" },
      { src: "part3-image/hack/splunk4.png", caption: "Splunk 로그 검색 화면" },
      { src: "part3-image/hack/splunk5.png", caption: "위협 탐지 현황 대시보드" }
    ]
  },
];

// 2. DOM 요소 선택
const grid = document.getElementById('project-grid');
const tabs = document.querySelectorAll('.tab-btn');

// 단계별 표시 이름 매핑
const categoryLabels = {
  phase1: 'Phase 1. Foundation',
  phase2: 'Phase 2. Integration',
  phase3: 'Phase 3. Analysis',
  phase4: 'Phase 4. Team Project'
};

// 3. 렌더링 함수
function renderProjects(filter = 'all') {
  grid.innerHTML = '';
  grid.style.opacity = '0';

  setTimeout(() => {
    const filtered = filter === 'all' 
      ? portfolioData 
      : portfolioData.filter(p => p.category === filter);

    if (filtered.length === 0) {
      grid.innerHTML = `<div style="grid-column:1/-1; text-align:center; padding:3rem; color:#64748b;">프로젝트 준비 중입니다.</div>`;
    } else {
      filtered.forEach((project, index) => {
        const card = document.createElement('div');
        card.className = 'card';
        card.style.animation = `fadeInUp 0.5s ease forwards ${index * 0.05}s`;
        card.onclick = () => openModal(project.id);
        
        let imgHTML = '';
        if (project.images && project.images.length > 0) {
           imgHTML = `<img src="${project.images[0].src}" alt="${project.title}" class="card-img" loading="lazy">`;
        } else {
           const match = project.htmlContent ? project.htmlContent.match(/<img[^>]+src="([^">]+)"/) : null;
           if (match) {
             imgHTML = `<img src="${match[1]}" alt="${project.title}" class="card-img" loading="lazy">`;
           } else {
             imgHTML = `<div style="width:100%; height:100%; background:linear-gradient(135deg,#1e293b,#0f172a); display:flex; align-items:center; justify-content:center;"><i class="ph-fill ph-code" style="font-size:3rem; opacity:0.2;"></i></div>`;
           }
        }
        
        const displayCategory = categoryLabels[project.category] || 'Project';

        card.innerHTML = `
          <div class="card-img-wrapper">${imgHTML}</div>
          <div class="card-body">
            <div style="display:flex; justify-content:space-between; align-items:start;">
               <span class="card-tag" style="color:${getPhaseColor(project.category)}">${displayCategory}</span>
               <i class="ph-bold ph-arrow-up-right" style="font-size:0.8rem; color:var(--text-muted);"></i>
            </div>
            <h3 class="card-title">${project.title}</h3>
            <p class="card-desc">${project.desc}</p>
            <div class="card-footer">
              ${project.tech.slice(0, 3).map(t => `<span class="tech-badge">${t}</span>`).join('')}
              ${project.tech.length > 3 ? `<span class="tech-badge">+${project.tech.length - 3}</span>` : ''}
            </div>
          </div>
        `;
        grid.appendChild(card);
      });
    }
    grid.style.opacity = '1';
  }, 200);
}

function getPhaseColor(category) {
  if (category === 'phase1') return '#22d3ee';
  if (category === 'phase2') return '#a855f7';
  if (category === 'phase3') return '#f472b6';
  if (category === 'phase4') return '#fb923c';
  return '#94a3b8';
}

function updateCounts() {
  document.getElementById('count-all').textContent = portfolioData.length;
  // 배열 안에 'phase4' 추가
  ['phase1', 'phase2', 'phase3', 'phase4'].forEach(cat => {
    const count = portfolioData.filter(p => p.category === cat).length;
    const badge = document.getElementById(`count-${cat}`);
    if(badge) badge.textContent = count; // 에러 방지를 위해 if문 살짝 보강
  });
}

tabs.forEach(tab => {
  tab.addEventListener('click', () => {
    tabs.forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    renderProjects(tab.dataset.category);
  });
});

// 6. 모달 로직
const modalOverlay = document.getElementById('modal-overlay');
const modalIcon = document.getElementById('modal-icon');
const modalTitle = document.getElementById('modal-title');
const modalCategory = document.getElementById('modal-category');
const modalDesc = document.getElementById('modal-desc');
const htmlContentBox = document.getElementById('modal-html-content');
const carouselTrack = document.getElementById('carousel-track');
const carouselContainer = document.getElementById('carousel-container');
const prevBtn = document.getElementById('prev-btn');
const nextBtn = document.getElementById('next-btn');

let currentSlide = 0;
let totalSlides = 0;

function openModal(id) {
  const project = portfolioData.find(p => p.id === id);
  if (!project) return;

  modalTitle.textContent = project.title;
  modalCategory.textContent = categoryLabels[project.category];
  
  if (project.htmlContent) {
    modalDesc.style.display = 'none';
    htmlContentBox.innerHTML = project.htmlContent;
    htmlContentBox.style.display = 'block';
  } else {
    modalDesc.textContent = project.desc;
    modalDesc.style.display = 'block';
    htmlContentBox.style.display = 'none';
  }
  
  if (project.downloads && project.downloads.length > 0) {
    const downloadSection = document.createElement('div');
    downloadSection.className = 'download-section';
    
    let buttonsHTML = `
      <div class="download-title"><i class="ph-bold ph-download"></i> 자료 다운로드</div>
      <div class="btn-group">
    `;
    
    if (project.downloadDesc) {
      buttonsHTML += `<p class="download-description">${project.downloadDesc}</p>`;
    }
    
    buttonsHTML += `<div class="btn-group">`;
    project.downloads.forEach(file => {
      // target="_blank"를 추가하여 새 창에서 열리도록 변경했습니다.
      buttonsHTML += `
        <a href="${file.src}" target="_blank" class="btn-download-modal">
          <i class="ph-bold ph-file-arrow-down"></i> ${file.name}
        </a>
      `;
    });

    buttonsHTML += `</div>`;
    downloadSection.innerHTML = buttonsHTML;
    
    htmlContentBox.appendChild(downloadSection);
  }
  
  if (project.category === 'phase1') modalIcon.className = 'ph-fill ph-tree-structure';
  else if (project.category === 'phase2') modalIcon.className = 'ph-fill ph-circles-three-plus';
  else if (project.category === 'phase3') modalIcon.className = 'ph-fill ph-skull';
  else if (project.category === 'phase4') modalIcon.className = 'ph-fill ph-users-three';
  else modalIcon.className = 'ph-fill ph-code';

  // 캐러셀 설정
  carouselTrack.innerHTML = '';
  currentSlide = 0;
  
  if (project.images && project.images.length > 0) {
    totalSlides = project.images.length;
    project.images.forEach(img => {
      const slide = document.createElement('div');
      slide.className = 'carousel-slide';
      slide.innerHTML = `<img src="${img.src}" alt="${img.caption}"><div class="carousel-caption">${img.caption}</div>`;
      carouselTrack.appendChild(slide);
    });
    updateCarousel();
    carouselContainer.style.display = 'block';
  } else {
    carouselContainer.style.display = 'none';
  }

  modalOverlay.classList.add('active');
  document.body.style.overflow = 'hidden';
}

function closeModal() {
  modalOverlay.classList.remove('active');
  document.body.style.overflow = '';
}

document.getElementById('modal-close').addEventListener('click', closeModal);
modalOverlay.addEventListener('click', (e) => { if (e.target === modalOverlay) closeModal(); });

// ★ 화살표 색상 죽이는 로직 추가
function updateCarousel() {
  carouselTrack.style.transform = `translateX(-${currentSlide * 100}%)`;
  
  // 첫 번째 슬라이드일 때 이전 버튼 회색 처리
  if (currentSlide === 0) {
    prevBtn.style.opacity = '0.3';
    prevBtn.style.cursor = 'default';
  } else {
    prevBtn.style.opacity = '1';
    prevBtn.style.cursor = 'pointer';
  }

  // 마지막 슬라이드일 때 다음 버튼 회색 처리
  if (currentSlide === totalSlides - 1) {
    nextBtn.style.opacity = '0.3';
    nextBtn.style.cursor = 'default';
  } else {
    nextBtn.style.opacity = '1';
    nextBtn.style.cursor = 'pointer';
  }
}

prevBtn.addEventListener('click', () => {
  if (currentSlide > 0) { 
    currentSlide--; 
    updateCarousel(); 
  }
});

nextBtn.addEventListener('click', () => {
  const slides = document.querySelectorAll('.carousel-slide');
  if (currentSlide < slides.length - 1) { 
    currentSlide++; 
    updateCarousel(); 
  }
});

const sections = document.querySelectorAll('section');
const navLinks = document.querySelectorAll('.nav-link');
window.addEventListener('scroll', () => {
  let current = '';
  sections.forEach(section => {
    const sectionTop = section.offsetTop;
    if (pageYOffset >= sectionTop - 150) current = section.getAttribute('id');
  });
  navLinks.forEach(link => {
    link.classList.remove('active');
    if (link.getAttribute('href').includes(current)) link.classList.add('active');
  });
});

updateCounts();
renderProjects('all');

// ================= [ 이력서 뷰어 로직 ] =================
const resumeTrack = document.getElementById('resume-track');
const resumePages = document.querySelectorAll('.resume-page');
const resumePrevBtn = document.getElementById('resume-prev');
const resumeNextBtn = document.getElementById('resume-next');
const resumeIndicator = document.getElementById('resume-page-indicator');

let currentResumePage = 0;
const totalResumePages = resumePages.length;

function updateResumeView() {
  if(totalResumePages === 0) return;
  
  // 슬라이드 이동
  resumeTrack.style.transform = `translateX(-${currentResumePage * 100}%)`;
  
  // 페이지 번호 업데이트
  resumeIndicator.textContent = `Page ${currentResumePage + 1} / ${totalResumePages}`;

  // 버튼 활성화/비활성화 (투명도 조절)
  resumePrevBtn.style.opacity = currentResumePage === 0 ? '0.3' : '1';
  resumePrevBtn.style.cursor = currentResumePage === 0 ? 'default' : 'pointer';
  
  resumeNextBtn.style.opacity = currentResumePage === totalResumePages - 1 ? '0.3' : '1';
  resumeNextBtn.style.cursor = currentResumePage === totalResumePages - 1 ? 'default' : 'pointer';
}

if (resumePrevBtn && resumeNextBtn) {
  resumePrevBtn.addEventListener('click', () => {
    if (currentResumePage > 0) {
      currentResumePage--;
      updateResumeView();
    }
  });

  resumeNextBtn.addEventListener('click', () => {
    if (currentResumePage < totalResumePages - 1) {
      currentResumePage++;
      updateResumeView();
    }
  });

  // 초기 실행
  updateResumeView();
}
