document.addEventListener('DOMContentLoaded', () => {
    const authForm = document.getElementById('authForm');
    const submitBtn = document.querySelector('.submit-btn');
    const loginCard = document.querySelector('.login-card');

    authForm.addEventListener('submit', (e) => {
        e.preventDefault();

        const email = document.getElementById('email').value.trim();
        const password = document.getElementById('password').value.trim();

        if (email === '' || password === '') {
            loginCard.classList.remove('shake');
            void loginCard.offsetWidth; // trigger reflow
            loginCard.classList.add('shake');
            return;
        }

        submitBtn.classList.add('loading');
        submitBtn.disabled = true;

        setTimeout(() => {
            submitBtn.classList.remove('loading');

            // Success State
            const btnSpan = submitBtn.querySelector('span');
            btnSpan.textContent = 'Mission Successful';
            btnSpan.style.opacity = '1';
            submitBtn.style.background = 'linear-gradient(45deg, #10b981, #059669)';

            setTimeout(() => {
                submitBtn.disabled = false;
                btnSpan.textContent = 'Launch Sequence';
                submitBtn.style.background = '';
                authForm.reset();
            }, 2000);

        }, 1500);
    });
});
