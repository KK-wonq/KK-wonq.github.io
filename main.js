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
      { src: "port_images/default_GNS3_ping_test.PNG", caption: "Ping 통신 테스트" }
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
      { src: "port_images/pfsense_main_dashboard.PNG", caption: "Pfsense 메인 대시보드" },
      { src: "port_images/pfsense_rule_1.PNG", caption: "방화벽 정책(Rule) 설정" },
      { src: "port_images/pfsense_haproxy.PNG", caption: "HAProxy 로드밸런싱" }
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
      { src: "port_images/suricata_install.PNG", caption: "Suricata 설치 및 실행" },
      { src: "port_images/suricata_test.PNG", caption: "fast.log 탐지 확인" }
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
      { src: "port_images/OSSEC(HIDS)_manage.PNG", caption: "에이전트 키 관리" }
    ]
  },
  {
    id: 'p1_zabbix',
    category: 'phase1',
    title: 'Zabbix 모니터링',
    desc: 'NMS Zabbix를 이용한 서버/네트워크 리소스 및 트래픽 시각화',
    tech: ['Zabbix', 'NMS', 'SNMP'],
    images: [
      { src: "port_images/zabbix_dashboard.PNG", caption: "Zabbix 대시보드" },
      { src: "port_images/zabbix_graph.PNG", caption: "트래픽 그래프 분석" }
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
      { src: "port_images/images-part/GNS3/pfrule.png", caption: "통합 방화벽 정책" }
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
      { src: "port_images/images-part/DNS,LOG,ANAlyzer,DB/mariadb.png", caption: "MariaDB 구동 확인" }
    ]
  },
  {
    id: 'p2_log',
    category: 'phase2',
    title: '중앙 로그 분석 시스템',
    desc: 'Rsyslog로 전사 로그 수집 및 LogAnalyzer를 통한 시각화',
    tech: ['Rsyslog', 'LogAnalyzer', 'Centralized Log'],
    htmlContent: `
      <p>각 서버(Web, DB, FW)에서 발생하는 Syslog를 중앙 서버로 전송하도록 설정하고, LogAnalyzer 웹 인터페이스를 통해 효율적으로 분석할 수 있는 환경을 구축했습니다.</p>
    `,
    images: [
      { src: "port_images/images-part/DNS,LOG,ANAlyzer,DB/loganalyzer.png", caption: "LogAnalyzer 분석 화면" }
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
      { src: "port_images/images-part/Samba,nfs/samba-set.png", caption: "Samba 설정 (smb.conf)" },
      { src: "port_images/images-part/Samba,nfs/samba-window.png", caption: "Windows 공유 폴더 접근" }
    ]
  },
  {
    id: 'p2_nfs',
    category: 'phase2',
    title: 'NFS 스토리지 공유',
    desc: 'Linux 서버 간 고속 데이터 공유를 위한 NFS 마운트 설정',
    tech: ['NFS', 'Linux', 'Storage'],
    images: [
      { src: "port_images/images-part/Samba,nfs/nfs-client.png", caption: "NFS 마운트 확인" }
    ]
  },
  {
    id: 'p2_linux_sec',
    category: 'phase2',
    title: 'Linux 보안 하드닝',
    desc: '서버 계정 관리, SSH 포트 변경, Firewalld 정책 적용',
    tech: ['Linux', 'Hardening', 'SSH'],
    images: [
      { src: "port_images/images-part/Linux/linux-user.png", caption: "계정 및 그룹 관리" },
      { src: "port_images/images-part/Linux/linux-firewall.png", caption: "Firewalld 포트 설정" }
    ]
  },

  // ================= [ Phase 3 : Analysis & Hacking (심화) ] =================
  {
    id: 'p3_topology',
    category: 'phase3',
    title: 'GNS3 심화 토폴로지 (Advanced)',
    desc: 'Phase 3를 위한 고도화된 보안 토폴로지 설계 및 구축',
    tech: ['GNS3', 'Advanced Design', 'Integration'],
    // ★ Phase 3 토폴로지 이미지 (part2-image 폴더 사용)
    images: [
      { src: "part2-image/GNS3/topology.png", caption: "Phase 3 심화 통합 토폴로지" }
    ]
  },
  {
    id: 'p3_wazuh',
    category: 'phase3',
    title: 'Wazuh SIEM 관제',
    desc: '오픈소스 SIEM Wazuh를 활용한 보안 이벤트 수집 및 대시보드 모니터링',
    tech: ['Wazuh', 'SIEM', 'ELK Stack'],
    images: [
      { src: "part2-image/wazuh,go,pmm/wazuh-1.png", caption: "Wazuh 이벤트 대시보드" },
      { src: "port_images/images-part/wazuh.PNG", caption: "에이전트 연결 확인" }
    ]
  },
  {
    id: 'p3_pmm',
    category: 'phase3',
    title: 'PMM DB 성능 분석',
    desc: 'PMM을 이용한 DB 쿼리 성능 분석 및 슬로우 쿼리 식별',
    tech: ['PMM', 'Database', 'Performance'],
    images: [
      { src: "part2-image/wazuh,go,pmm/pmm-1.png", caption: "PMM 대시보드" },
      { src: "port_images/images-part/wazuh,go,pmm/pmm-2.png", caption: "Query Analytics" }
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
        <img src="part2-image/Juicy/login-admin/1-3.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="SQLi">
      </div>

      <div style="background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; padding: 20px; margin-top: 20px;">
        <h4 style="color: #f472b6; margin-top: 0;">2. DOM XSS</h4>
        <p>검색창(Search)에 스크립트 태그를 삽입하여 사용자 브라우저에서 임의의 코드가 실행되도록 했습니다.</p>
        <img src="part2-image/Juicy/dom/7-4.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="XSS">
      </div>

      <div style="background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; padding: 20px; margin-top: 20px;">
        <h4 style="color: #a855f7; margin-top: 0;">3. Kill Chatbot (Logic Flaw)</h4>
        <p>챗봇 소스 코드를 분석하여 특정 로직의 취약점을 이용해 챗봇 서비스를 비활성화시켰습니다.</p>
        <img src="part2-image/Juicy/kill/9-1.png" style="width:100%; border-radius:6px; margin-top:10px;" alt="Chatbot">
      </div>
    `,
    images: [
      { src: "part2-image/Juicy/juicy-nail.png", caption: "Juice Shop 메인" },
      { src: "part2-image/Juicy/login-admin/1-3.png", caption: "SQL Injection 성공" },
      { src: "part2-image/Juicy/dom/7-4.png", caption: "DOM XSS Alert" }
    ]
  },
  {
    id: 'p3_venus',
    category: 'phase3',
    title: 'CTF - Vulnhub Venus',
    desc: '포트 스캔, 쿠키 변조, CVE-2021-3156 취약점을 이용한 Root 권한 탈취',
    tech: ['Penetration Test', 'Metasploit', 'Nmap'],
    htmlContent: `
      <h3>1. 정찰 (Reconnaissance)</h3>
      <p>Nmap 스캔을 통해 22(SSH), 80(HTTP) 포트 오픈 확인.</p>
      <img src="port_images/images-part/ctf/ctf-nmap.png" style="width:100%; border-radius:8px;" alt="Nmap">
      <h3>2. 침투 및 권한 상승</h3>
      <p>패킷 캡처로 자격 증명 획득 후, Sudo 취약점(CVE-2021-3156)을 악용하여 Root 획득.</p>
      <img src="port_images/images-part/ctf/rootflag.png" style="width:100%; border-radius:8px;" alt="Root Flag">
    `,
    images: [
      { src: "port_images/images-part/ctf/ctf-1(ip).png", caption: "타겟 IP 스캔" },
      { src: "port_images/images-part/ctf/rootflag.png", caption: "Root Flag 획득" }
    ]
  },
  {
    id: 'p3_bluemoon',
    category: 'phase3',
    title: 'CTF - Bluemoon Docker',
    desc: 'FTP 취약점 공략 및 Docker Container Escape 기법 연구',
    tech: ['Docker Escape', 'FTP Exploit', 'Linux'],
    htmlContent: `
      <h3>Docker 탈출 (Container Escape)</h3>
      <p>FTP 익명 로그인 취약점으로 침투 후, Docker 그룹 권한을 악용하여 호스트 파일 시스템을 마운트하고 Root 권한을 탈취했습니다.</p>
    `,
    images: [
      { src: "part2-image/ctf/bluemoon.png", caption: "Bluemoon 타겟 분석" }
    ]
  },
  {
    id: 'p3_malware',
    category: 'phase3',
    title: '악성코드 분석 (Mimikatz)',
    desc: 'Flare-VM 환경에서의 Mimikatz SSP 인젝션 기법 상세 리버싱',
    tech: ['Reverse Engineering', 'IDA Pro', 'x64dbg'],
    htmlContent: `
      <h3>분석 개요</h3>
      <p>Mimikatz가 lsass.exe 프로세스에 악성 DLL을 주입하여 비밀번호를 탈취하는 원리를 분석했습니다.</p>
      <img src="part2-image/flare-vm/2.png" style="width:100%; border-radius:8px;" alt="IDA Pro 분석">
    `,
    images: [
      { src: "part2-image/flare-vm/1.png", caption: "PE Studio 분석" }
    ]
  }
];

// 2. DOM 요소 선택
const grid = document.getElementById('project-grid');
const tabs = document.querySelectorAll('.tab-btn');

// 단계별 표시 이름 매핑
const categoryLabels = {
  phase1: 'Phase 1. Foundation',
  phase2: 'Phase 2. Integration',
  phase3: 'Phase 3. Analysis'
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
  return '#94a3b8';
}

function updateCounts() {
  document.getElementById('count-all').textContent = portfolioData.length;
  ['phase1', 'phase2', 'phase3'].forEach(cat => {
    const count = portfolioData.filter(p => p.category === cat).length;
    document.getElementById(`count-${cat}`).textContent = count;
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
  
  if (project.category === 'phase1') modalIcon.className = 'ph-fill ph-tree-structure';
  else if (project.category === 'phase2') modalIcon.className = 'ph-fill ph-circles-three-plus';
  else if (project.category === 'phase3') modalIcon.className = 'ph-fill ph-skull';
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
