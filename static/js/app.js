/* ThreatLedger client behaviour. No inline scripts anywhere (strict CSP in Phase 7):
 * - charts: <canvas data-chart="<json_script id>" data-type="line|bar" data-percent="1">
 * - print:  any element with data-action="print"
 */
(function () {
  "use strict";
  var BAND = { critical: "#dc2626", high: "#f97316", medium: "#eab308", low: "#22c55e" };
  var SERIES = ["#1f57bd", "#7c3aed", "#0891b2", "#db2777", "#65a30d", "#ea580c", "#475569"];

  function colourFor(dataset, index) {
    return BAND[dataset.band] || SERIES[index % SERIES.length];
  }

  function render(root) {
    if (typeof window.Chart === "undefined") { return; }
    root.querySelectorAll("canvas[data-chart]").forEach(function (canvas) {
      if (canvas.dataset.rendered) { return; }
      var source = document.getElementById(canvas.dataset.chart);
      if (!source) { return; }
      var data = JSON.parse(source.textContent);
      var type = canvas.dataset.type || "line";
      var stacked = type === "bar";
      data.datasets.forEach(function (d, i) {
        var c = colourFor(d, i);
        d.borderColor = c;
        d.backgroundColor = stacked ? c : c + "22";
        d.tension = 0.25;
        d.spanGaps = true;
        d.pointRadius = data.labels.length > 40 ? 0 : 3;
        d.fill = false;
      });
      canvas.dataset.rendered = "1";
      new window.Chart(canvas, {
        type: type,
        data: data,
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: false,
          interaction: { mode: "index", intersect: false },
          scales: {
            x: { stacked: stacked, ticks: { maxRotation: 0, autoSkip: true } },
            y: { stacked: stacked, beginAtZero: true, max: canvas.dataset.percent === "1" ? 100 : undefined }
          },
          plugins: { legend: { position: "bottom", labels: { boxWidth: 12 } } }
        }
      });
    });
  }

  document.addEventListener("DOMContentLoaded", function () { render(document); });
  document.addEventListener("htmx:afterSwap", function (e) { render(e.target); });
  document.addEventListener("click", function (e) {
    var el = e.target.closest ? e.target.closest("[data-action='print']") : null;
    if (el) { e.preventDefault(); window.print(); }
  });
})();
