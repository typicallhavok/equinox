// Minimal progressive enhancement: tab switching + fade-in on scroll.
(function () {
  "use strict";

  // --- Quickstart tabs ---
  document.querySelectorAll("[data-tabs]").forEach((group) => {
    const buttons = group.querySelectorAll(".tabs__btn");
    const panels = group.querySelectorAll(".tabs__panel");

    buttons.forEach((btn) => {
      btn.addEventListener("click", () => {
        const target = btn.dataset.tab;

        buttons.forEach((b) => {
          const active = b === btn;
          b.classList.toggle("is-active", active);
          b.setAttribute("aria-selected", active ? "true" : "false");
        });

        panels.forEach((panel) => {
          const active = panel.dataset.panel === target;
          panel.classList.toggle("is-active", active);
          panel.hidden = !active;
        });
      });
    });
  });

  const targets = document.querySelectorAll(
    ".card, .stat, .perf__copy, .perf__diagram, .run__col, .cta__inner, .terminal"
  );

  // Mark everything as a reveal target.
  targets.forEach((el) => el.classList.add("reveal"));

  if (!("IntersectionObserver" in window)) {
    targets.forEach((el) => el.classList.add("is-visible"));
    return;
  }

  const observer = new IntersectionObserver(
    (entries, obs) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          obs.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.12, rootMargin: "0px 0px -40px 0px" }
  );

  targets.forEach((el) => observer.observe(el));
})();
