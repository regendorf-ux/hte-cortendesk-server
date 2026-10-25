// The Overview's charts: the data arrives as JSON in each chart element's data-chart attribute.
(function () {
    "use strict";
    if (typeof ApexCharts === "undefined") { return; }

    function read(id) {
        var el = document.getElementById(id);
        if (!el || !el.getAttribute("data-chart")) { return null; }
        try { return { el: el, data: JSON.parse(el.getAttribute("data-chart")) }; } catch (e) { return null; }
    }

    var connections = read("chart-connections");
    var platforms = read("chart-platforms");
    var charts = [];

    // The palette lives in cortendesk.css as custom properties, which ApexCharts cannot read itself: they are resolved
    // off the root element on every render, which is also how the light/dark flip stays in sync.
    function theme() {
        var css = getComputedStyle(document.documentElement);
        var token = function (name) { return css.getPropertyValue(name).trim(); };
        return {
            series: ["--rd-blue", "--rd-accent-ink", "--rd-teal", "--rd-purple", "--rd-amber"].map(token),
            ink: token("--rd-ink"), muted: token("--rd-ink-muted"), grid: token("--rd-border"), surface: token("--rd-surface"),
            mode: document.documentElement.getAttribute("data-bs-theme") === "light" ? "light" : "dark"
        };
    }

    function base(t) {
        return {
            chart: { fontFamily: "inherit", foreColor: t.muted, toolbar: { show: false }, background: "transparent" },
            grid: { borderColor: t.grid, strokeDashArray: 3 },
            tooltip: { theme: t.mode },
            legend: { labels: { colors: t.muted }, markers: { size: 5 } },
            dataLabels: { enabled: false }
        };
    }

    function render() {
        charts.forEach(function (c) { c.destroy(); });
        charts = [];
        var t = theme();

        if (connections) {
            var d = connections.data;
            var days = d.labels.length;
            var ticks = Math.max(3, Math.floor((connections.el.clientWidth || 600) / 62));
            charts.push(new ApexCharts(connections.el, Object.assign(base(t), {
                chart: Object.assign(base(t).chart, { type: "bar", height: 300, stacked: true }),
                series: d.series,
                colors: t.series.slice(0, 3),
                plotOptions: { bar: { columnWidth: days > 60 ? "80%" : (days > 20 ? "62%" : "45%"), borderRadius: 3, borderRadiusApplication: "end", borderRadiusWhenStacked: "last" } },
                stroke: { show: true, width: 2, colors: [t.surface] },
                xaxis: { categories: d.labels, tickAmount: Math.min(days, ticks), axisBorder: { color: t.grid }, axisTicks: { show: false }, labels: { rotate: 0, hideOverlappingLabels: true } },
                yaxis: { labels: { formatter: function (v) { return Math.round(v); } } },
                legend: Object.assign(base(t).legend, { position: "bottom", horizontalAlign: "left", offsetY: 4 })
            })));
        }

        if (platforms && platforms.data.values.length > 0) {
            var p = platforms.data;
            charts.push(new ApexCharts(platforms.el, Object.assign(base(t), {
                chart: Object.assign(base(t).chart, { type: "donut", height: 240 }),
                series: p.values, labels: p.labels, colors: t.series.slice(0, p.labels.length),
                stroke: { width: 2, colors: [t.surface] },
                plotOptions: { pie: { donut: { size: "78%", labels: { show: true,
                    name: { fontSize: "12px", color: t.muted, offsetY: 20 },
                    value: { fontSize: "26px", fontWeight: 600, color: t.ink, offsetY: -14 },
                    total: { show: true, label: "Devices", color: t.muted, fontSize: "12px", formatter: function (w) { return w.globals.seriesTotals.reduce(function (a, b) { return a + b; }, 0); } }
                } } } },
                legend: { show: false }
            })));
        }

        charts.forEach(function (c) { c.render(); });
    }

    render();

    var timer;
    window.addEventListener("resize", function () { clearTimeout(timer); timer = setTimeout(render, 250); });
    new MutationObserver(function (muts) {
        muts.forEach(function (m) { if (m.attributeName === "data-bs-theme") { render(); } });
    }).observe(document.documentElement, { attributes: true });
})();
