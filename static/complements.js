// Si necesitas lógica del lado del cliente, déjala aquí.
// Por ejemplo, copiar al portapapeles:
document.addEventListener("click", (e) => {
  if (e.target.matches("[data-copy]")) {
    navigator.clipboard.writeText(e.target.dataset.copy || "");
  }
});
