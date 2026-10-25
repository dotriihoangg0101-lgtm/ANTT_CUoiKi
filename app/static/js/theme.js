// Nút chuyển chế độ Sáng / Tối. Chế độ ban đầu đã được đặt sớm trong <head> (base.html)
// để tránh nháy màu; file này chỉ xử lý thao tác bấm nút và lưu lựa chọn.
(function () {
    const STORAGE_KEY = "secgw-theme";
    const root = document.documentElement;

    function applyTheme(theme) {
        root.setAttribute("data-bs-theme", theme);
        document.querySelectorAll("[data-theme-toggle]").forEach(function (btn) {
            const next = theme === "dark" ? "sáng" : "tối";
            btn.setAttribute("aria-label", "Chuyển sang chế độ " + next);
            btn.setAttribute("title", "Chuyển sang chế độ " + next);
        });
    }

    applyTheme(root.getAttribute("data-bs-theme") || "dark");

    document.querySelectorAll("[data-theme-toggle]").forEach(function (btn) {
        btn.addEventListener("click", function () {
            const next = root.getAttribute("data-bs-theme") === "dark" ? "light" : "dark";
            applyTheme(next);
            try { localStorage.setItem(STORAGE_KEY, next); } catch (e) { /* trình duyệt chặn storage */ }
        });
    });

    // Bật hiệu ứng chuyển màu sau khi trang đã vẽ xong lần đầu
    requestAnimationFrame(function () { root.classList.add("theme-ready"); });
})();
