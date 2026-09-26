document.addEventListener("DOMContentLoaded", () => {
    // 1. Sticky Header Effect
    const header = document.querySelector("header");
    window.addEventListener("scroll", () => {
        if (window.scrollY > 50) {
            header.classList.add("scrolled");
        } else {
            header.classList.remove("scrolled");
        }
    });

    // 2. Scroll Reveal Animations (Intersection Observer)
    // Add 'hidden' class to elements we want to animate first
    const fadeUpElements = document.querySelectorAll('.fade-up, .fade-in, .stagger-card');
    fadeUpElements.forEach(el => el.classList.add('hidden'));

    const observerOptions = {
        root: null,
        rootMargin: '0px',
        threshold: 0.15
    };

    const observer = new IntersectionObserver((entries, observer) => {
        entries.forEach((entry, index) => {
            if (entry.isIntersecting) {
                // Stagger delay for cards
                if(entry.target.classList.contains('stagger-card')) {
                    setTimeout(() => {
                        entry.target.classList.add('show');
                        entry.target.classList.remove('hidden');
                    }, index * 150); // 150ms delay between each card
                } else {
                    entry.target.classList.add('show');
                    entry.target.classList.remove('hidden');
                }
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);

    fadeUpElements.forEach(el => observer.observe(el));

    // 3. 3D Mouse Tilt Animation for Hero Image
    const tiltImage = document.getElementById("tilt-image");
    const heroSection = document.querySelector(".hero");

    if (tiltImage && heroSection) {
        heroSection.addEventListener("mousemove", (e) => {
            const x = e.clientX;
            const y = e.clientY;
            
            // Calculate center of the screen
            const centerX = window.innerWidth / 2;
            const centerY = window.innerHeight / 2;
            
            // Calculate tilt amount (adjust the divider for stronger/weaker effect)
            const rotateX = ((y - centerY) / 30).toFixed(2);
            const rotateY = ((centerX - x) / 30).toFixed(2);
            
            tiltImage.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) scale3d(1.02, 1.02, 1.02)`;
        });

        // Reset image position when mouse leaves
        heroSection.addEventListener("mouseleave", () => {
            tiltImage.style.transform = `perspective(1000px) rotateX(0deg) rotateY(0deg) scale3d(1, 1, 1)`;
            tiltImage.style.transition = "transform 0.5s ease-out";
            
            // Remove transition after it resets so mousemove is smooth again
            setTimeout(() => {
                tiltImage.style.transition = "transform 0.1s ease-out"; 
            }, 500);
        });
    }
});