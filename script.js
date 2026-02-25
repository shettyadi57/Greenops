
        // smooth scroll already in CSS, but we can keep anchor behaviour
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                const href = this.getAttribute('href');
                if (href === "#") return;
                const target = document.querySelector(href);
                if (target) {
                    e.preventDefault();
                    target.scrollIntoView({ behavior: 'smooth' });
                }
            });
        });
    
function downloadAgent() {
    const os = navigator.platform.toLowerCase();

    if (os.includes('win')) {
        window.location.href = "downloads/GreenOps-Windows.exe";
    } 
    else if (os.includes('mac')) {
        window.location.href = "downloads/GreenOps-macOS.zip";
    } 
    else {
        window.location.href = "downloads/GreenOps-Linux";
    }
}


<button onclick="downloadAgent()" class="os-btn">
    Download for Your OS
</button>