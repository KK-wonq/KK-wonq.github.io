document.addEventListener('DOMContentLoaded', () => {
  
  // 0. 스플래시 스크린 로직
  const splash = document.getElementById("splash");
  if (splash) {
    window.addEventListener("load", () => {
      setTimeout(() => {
        splash.classList.add("fade-out");
      }, 1500);
    });
  }

  // 1. portfolioData 변수가 HTML에 정의되어 있는지 확인
  if (typeof portfolioData === 'undefined') {
    console.error("FATAL: portfolioData is not defined in the HTML file before loading main.js");
    // 각 HTML 파일의 <script> 태그 안에 const portfolioData = { ... }; 를 정의해야 합니다.
    return;
  }

  // 2. 모든 DOM 요소 가져오기
  const modal = document.getElementById('project-modal');
  const modalCloseBtn = document.getElementById('modal-close');
  const modalBackBtn = document.getElementById('modal-back');
  const modalTitle = document.getElementById('project-detail-title');
  const modalDescription = document.getElementById('project-detail-description');
  const modalContent = document.getElementById('project-detail-content');
  
  const lightbox = document.getElementById('lightbox');
  const lightboxImage = document.getElementById('lightbox-image');

  const navigationStack = []; // 뒤로가기를 위한 스택

  // 3. 핵심 렌더링 함수 (모든 케이스 처리)
  function renderModalContent(projectId) {
    const project = portfolioData[projectId];
    if (!project) return;

    if (navigationStack[navigationStack.length - 1] !== projectId) {
      navigationStack.push(projectId);
    }
      
    modalTitle.textContent = project.title;
    modalDescription.textContent = project.description;
    modalContent.innerHTML = ''; // 내용 초기화

    // [분기 1: 블로그 형식]
    if (project.htmlContent) {
      const blogContainer = document.createElement('div');
      blogContainer.className = 'blog-content'; // CSS가 스타일을 적용
      blogContainer.innerHTML = project.htmlContent;
      modalContent.appendChild(blogContainer);

      blogContainer.querySelectorAll('img').forEach(img => {
        img.addEventListener('click', () => openLightbox(img.src));
        img.style.cursor = 'zoom-in';
      });
    } 
    // [분기 2: 이미지 그리드 또는 하위 프로젝트]
    else if (project.images || project.subProjects) {
      const grid = document.createElement('div');
      // ★★★ CSS 클래스 이름 통일 ('detail-images-grid' 또는 'projects-grid')
      // 'projects-grid'를 사용하면 메인 페이지와 똑같은 카드 레이아웃이 나옵니다.
      grid.className = 'projects-grid'; 

      // 2-1. 하위 프로젝트가 있으면 (subProjects)
      if (project.subProjects) {
        for (const key in project.subProjects) {
          const sub = project.subProjects[key];
          const card = document.createElement('div');
          card.className = 'project-card'; // 메인 페이지 카드 스타일 재사용
          card.tabIndex = 0;
          card.innerHTML = `<img src="${sub.thumbnail}" alt="${sub.title}" class="project-card-thumbnail"><div class="project-card-content"><p>${sub.title}</p></div>`;
          card.addEventListener('click', () => renderModalContent(key));
          grid.appendChild(card);
        }
      }

      // 2-2. 이미지만 있으면 (images)
      if (project.images) {
        // 이미지는 'detail-image-item' 스타일을 사용하는게 더 적절할 수 있습니다.
        // 여기서는 .project-card와 유사하게 만듭니다.
        const imageGrid = document.createElement('div');
        imageGrid.className = 'detail-images-grid'; // CSS에 정의된 그리드 사용

        project.images.forEach(image => {
          const item = document.createElement('div');
          item.className = 'detail-image-item';
          item.innerHTML = `
            <img src="${image.src}" alt="${image.caption}" loading="lazy">
            <p>${image.caption}</p>
          `;
          item.addEventListener('click', () => openLightbox(image.src));
          imageGrid.appendChild(item);
        });
        modalContent.appendChild(imageGrid);
      }
      
      // 하위 프로젝트가 있을 경우에만 grid를 추가합니다.
      if (project.subProjects) {
        modalContent.appendChild(grid);
      }
    }
      
    modalBackBtn.style.display = navigationStack.length > 1 ? 'block' : 'none';
  }

  // 4. 나머지 헬퍼 함수
  function openModal(projectId) {
    navigationStack.length = 0; 
    renderModalContent(projectId);
    modal.classList.add('active');
    document.body.style.overflow = 'hidden';
  }

  function closeModal() {
    modal.classList.remove('active');
    document.body.style.overflow = '';
  }

  function goBack() {
    navigationStack.pop();
    if (navigationStack.length > 0) {
      const prevProjectId = navigationStack[navigationStack.length - 1];
      renderModalContent(prevProjectId);
    }
  }

  function openLightbox(src) {
    lightboxImage.src = src;
    lightbox.classList.add('active');
  }

  function closeLightbox() {
    lightbox.classList.remove('active');
  }

  // 5. 이벤트 리스너 연결
  document.querySelectorAll('.project-card').forEach(card => {
    const projectId = card.dataset.projectId;
    if (projectId) { // data-project-id가 있는 카드만
      card.addEventListener('click', () => openModal(projectId));
      card.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') openModal(projectId);
      });
    }
  });

  if (modalCloseBtn) modalCloseBtn.addEventListener('click', closeModal);
  if (modalBackBtn) modalBackBtn.addEventListener('click', goBack);
  if (modal) modal.addEventListener('click', (e) => {
    if (e.target === modal) closeModal();
  });
  
  if (lightbox) lightbox.addEventListener('click', closeLightbox);
    
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (lightbox.classList.contains('active')) closeLightbox();
      else if (modal.classList.contains('active')) closeModal();
    }
  });
});
