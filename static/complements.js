
document.addEventListener("click", (e) => {
  if (e.target.matches("[data-copy]")) {
    navigator.clipboard.writeText(e.target.dataset.copy || "");
  }
});
