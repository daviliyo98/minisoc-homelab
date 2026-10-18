// MINISOC - portal. JS mínimo y en fichero propio (no inline) para que la
// Content-Security-Policy pueda prohibir scripts en línea: script-src 'self'.
// Todo funciona sin JS; esto solo añade comodidades.
document.documentElement.classList.add("js");

document.addEventListener("DOMContentLoaded", () => {
  // "Copiar dirección" / "Copiar URL". El portal va por http en la tailnet y
  // navigator.clipboard exige contexto seguro, así que hay plan B con un textarea.
  document.querySelectorAll("[data-copiar]").forEach((btn) => {
    const original = btn.textContent;
    btn.addEventListener("click", async () => {
      const texto = btn.dataset.copiar;
      let ok = false;
      try {
        await navigator.clipboard.writeText(texto);
        ok = true;
      } catch {
        const area = document.createElement("textarea");
        area.value = texto;
        area.setAttribute("readonly", "");
        area.style.position = "fixed";
        area.style.opacity = "0";
        document.body.appendChild(area);
        area.select();
        ok = document.execCommand("copy");
        area.remove();
      }
      btn.textContent = ok ? "Copiada" : "No se pudo copiar";
      btn.classList.toggle("copiado", ok);
      setTimeout(() => { btn.textContent = original; btn.classList.remove("copiado"); }, 1600);
    });
  });

  // En pantallas estrechas la ficha queda debajo de la lista: al elegir un
  // servicio, bajar hasta ella.
  const ficha = document.getElementById("ficha");
  if (ficha && new URLSearchParams(location.search).has("sel") && matchMedia("(max-width: 900px)").matches) {
    ficha.scrollIntoView({ block: "start" });
  }

  // Flechas arriba/abajo para recorrer la lista sin ratón, como en un gestor de correo.
  const filas = [...document.querySelectorAll(".lista a.fila")];
  document.addEventListener("keydown", (ev) => {
    if (!filas.length || ev.target.closest("input, textarea, select")) return;
    if (ev.key !== "ArrowDown" && ev.key !== "ArrowUp") return;
    const actual = filas.findIndex((f) => f.getAttribute("aria-current") === "true");
    const sig = Math.max(0, Math.min(filas.length - 1, actual + (ev.key === "ArrowDown" ? 1 : -1)));
    if (sig !== actual) {
      ev.preventDefault();
      location.href = filas[sig].href;
    }
  });
});
