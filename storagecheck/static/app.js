const state = {
    targets: [],
    selectedTargetId: null,
    selectedScanId: null,
    currentPath: null,
    currentView: null,
    scanList: [],
    formMode: "create",
};

const refs = {
    addTargetButton: document.getElementById("add-target-button"),
    targetList: document.getElementById("target-list"),
    heroTitle: document.getElementById("hero-title"),
    heroSubtitle: document.getElementById("hero-subtitle"),
    metricsGrid: document.getElementById("metrics-grid"),
    tableContainer: document.getElementById("table-container"),
    explorerHeader: document.getElementById("explorer-header"),
    historyContainer: document.getElementById("history-container"),
    scanList: document.getElementById("scan-list"),
    scanNowButton: document.getElementById("scan-now-button"),
    editTargetButton: document.getElementById("edit-target-button"),
    refreshButton: document.getElementById("refresh-button"),
    dialog: document.getElementById("target-dialog"),
    dialogTitle: document.getElementById("dialog-title"),
    closeDialogButton: document.getElementById("close-dialog-button"),
    cancelDialogButton: document.getElementById("cancel-dialog-button"),
    form: document.getElementById("target-form"),
    labelInput: document.getElementById("target-label"),
    rootPathInput: document.getElementById("target-root-path"),
    scanModeInput: document.getElementById("target-scan-mode"),
    sizeStrategyInput: document.getElementById("target-size-strategy"),
    maxDepthInput: document.getElementById("target-max-depth"),
    scheduleTypeInput: document.getElementById("target-schedule-type"),
    intervalHoursInput: document.getElementById("target-interval-hours"),
    dailyTimeInput: document.getElementById("target-daily-time"),
    enabledInput: document.getElementById("target-enabled"),
    intervalWrapper: document.getElementById("interval-wrapper"),
    timeWrapper: document.getElementById("time-wrapper"),
    toastContainer: document.getElementById("toast-container"),
};

async function api(url, options = {}) {
    const response = await fetch(url, {
        headers: {
            "Content-Type": "application/json",
            ...(options.headers || {}),
        },
        ...options,
    });
    if (!response.ok) {
        let detail = response.statusText;
        try {
            const payload = await response.json();
            detail = payload.detail || JSON.stringify(payload);
        } catch (error) {
            detail = response.statusText;
        }
        throw new Error(detail);
    }
    const text = await response.text();
    if (!text) {
        return null;
    }
    return JSON.parse(text);
}

function showToast(message, type = "info") {
    const element = document.createElement("div");
    element.className = `toast ${type === "error" ? "error" : ""}`;
    element.textContent = message;
    refs.toastContainer.appendChild(element);
    window.setTimeout(() => {
        element.remove();
    }, 3600);
}

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

function formatBytes(bytes) {
    const value = Number(bytes || 0);
    if (!Number.isFinite(value) || value <= 0) {
        return "0 B";
    }
    const units = ["B", "KB", "MB", "GB", "TB", "PB"];
    let size = value;
    let unitIndex = 0;
    while (size >= 1024 && unitIndex < units.length - 1) {
        size /= 1024;
        unitIndex += 1;
    }
    const digits = size >= 100 ? 0 : size >= 10 ? 1 : 2;
    return `${size.toFixed(digits)} ${units[unitIndex]}`;
}

function formatCount(value) {
    return Number(value || 0).toLocaleString("zh-CN");
}

function formatDate(isoString) {
    if (!isoString) {
        return "--";
    }
    const date = new Date(isoString);
    return date.toLocaleString("zh-CN", {
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
    });
}

function formatPercent(value) {
    return `${(value * 100).toFixed(value >= 0.1 ? 1 : 2)}%`;
}

function formatDelta(currentValue, previousValue) {
    if (previousValue == null) {
        return "首次记录";
    }
    const delta = currentValue - previousValue;
    if (delta === 0) {
        return "无变化";
    }
    const sign = delta > 0 ? "+" : "-";
    return `${sign}${formatBytes(Math.abs(delta))}`;
}

function formatDuration(startedAt) {
    if (!startedAt) {
        return "--";
    }
    const elapsedSeconds = Math.max(0, Math.floor((Date.now() - new Date(startedAt).getTime()) / 1000));
    const hours = Math.floor(elapsedSeconds / 3600);
    const minutes = Math.floor((elapsedSeconds % 3600) / 60);
    const seconds = elapsedSeconds % 60;
    if (hours > 0) {
        return `${hours}h ${String(minutes).padStart(2, "0")}m`;
    }
    return `${minutes}m ${String(seconds).padStart(2, "0")}s`;
}

function scheduleLabel(target) {
    if (!target.enabled) {
        return "已暂停";
    }
    if (target.schedule_type === "manual") {
        return "仅手动";
    }
    if (target.schedule_type === "hourly") {
        return `每 ${target.interval_hours || 1} 小时`;
    }
    if (target.schedule_type === "daily") {
        return `每天 ${target.daily_time || "09:00"}`;
    }
    return "--";
}

function modeLabel(target) {
    if (!target) {
        return "--";
    }
    return target.scan_mode === "full" ? "完整保存" : `按层保存 / ${target.max_depth} 层`;
}

function scanModeLabel(scan) {
    return scan.mode === "full" ? "完整保存" : `按层 ${scan.max_depth} 层`;
}

function sizeStrategyLabel(strategy) {
    return strategy === "logical" ? "极速 / 逻辑大小" : "精确 / 实际占用";
}

function engineLabel(engine) {
    return engine === "ntfs_mft" ? "NTFS MFT" : "\u9012\u5f52\u626b\u63cf";
}

function selectedTarget() {
    return state.targets.find((target) => target.id === state.selectedTargetId) || null;
}

function selectedCompletedScan() {
    return state.scanList.find((scan) => scan.id === state.selectedScanId && scan.status === "completed") || null;
}

function selectedActiveScan() {
    return selectedTarget()?.active_scan || null;
}

function progressForScan(scan) {
    if (scan.progress) {
        return scan.progress;
    }
    const activeScan = selectedActiveScan();
    if (!activeScan || !activeScan.scan_id) {
        return null;
    }
    return activeScan.scan_id === scan.id ? activeScan : null;
}

function isBusyScanStatus(status) {
    return ["running", "starting", "queued", "stopping", "finalizing"].includes(status);
}

function setDialogVisibility() {
    const scheduleType = refs.scheduleTypeInput.value;
    refs.intervalWrapper.classList.toggle("hidden", scheduleType !== "hourly");
    refs.timeWrapper.classList.toggle("hidden", scheduleType !== "daily");
    refs.maxDepthInput.disabled = refs.scanModeInput.value === "full";
}

function renderTargets() {
    if (!state.targets.length) {
        refs.targetList.innerHTML = '<div class="target-card"><p class="brand-copy">还没有目标。先把 C:\\ 加进来试试。</p></div>';
        return;
    }
    refs.targetList.innerHTML = state.targets
        .map((target) => {
            const latestSize = target.last_scan_status ? formatBytes(target.last_scan_size_bytes || 0) : "--";
            const activeScan = target.active_scan;
            const statusTag = activeScan
                ? '<span class="small-tag running">扫描中</span>'
                : target.last_scan_status === "failed"
                    ? '<span class="small-tag danger">上次失败</span>'
                    : '<span class="small-tag success">可用</span>';
            const progressMeta = activeScan
                ? `<p class="small-meta">\u5df2\u626b ${formatCount(activeScan.processed_entry_count)} \u9879 | ${formatBytes(activeScan.scanned_size_bytes)} | ${escapeHtml(engineLabel(activeScan.engine))} | ${escapeHtml(sizeStrategyLabel(activeScan.size_strategy))}</p>`
                : "";
            return `
                <article class="target-card ${target.id === state.selectedTargetId ? "selected" : ""}" data-target-id="${target.id}">
                    <div class="target-card-header">
                        <div>
                            <h3 class="target-title">${escapeHtml(target.label)}</h3>
                            <p class="small-meta">${escapeHtml(target.root_path)}</p>
                        </div>
                        ${statusTag}
                    </div>
                    <div class="legend">
                        <span class="small-tag">${escapeHtml(scheduleLabel(target))}</span>
                        <span class="small-tag warn">${escapeHtml(modeLabel(target))}</span>
                        <span class="small-tag">${escapeHtml(sizeStrategyLabel(target.size_strategy))}</span>
                    </div>
                    <div>
                        <p class="small-meta">最近容量</p>
                        <strong>${latestSize}</strong>
                        ${progressMeta}
                    </div>
                    <div class="target-card-actions">
                        <button class="row-button" data-action="select" data-target-id="${target.id}">查看</button>
                        <button class="row-button" data-action="${activeScan ? "stop" : "scan"}" data-target-id="${target.id}">${activeScan ? (activeScan.cancel_requested ? "\u6b63\u5728\u505c\u6b62..." : "\u4e2d\u65ad") : "\u626b\u63cf"}</button>
                        <button class="row-button danger" data-action="delete" data-target-id="${target.id}" ${activeScan ? "disabled" : ""}>${activeScan ? "\u626b\u63cf\u4e2d\u4e0d\u53ef\u5220\u9664" : "\u5220\u9664"}</button>
                    </div>
                </article>
            `;
        })
        .join("");
}

function renderHero() {
    const target = selectedTarget();
    const activeScan = selectedActiveScan();
    refs.scanNowButton.disabled = !target;
    refs.editTargetButton.disabled = !target;
    refs.scanNowButton.textContent = activeScan ? (activeScan.cancel_requested ? "\u6b63\u5728\u505c\u6b62..." : "\u4e2d\u65ad\u626b\u63cf") : "\u7acb\u5373\u626b\u63cf";
    if (!target) {
        refs.heroTitle.textContent = "先添加一个扫描目标";
        refs.heroSubtitle.textContent = "支持手动扫描、每小时扫描、每天定时扫描。";
        renderMetrics();
        return;
    }
    refs.heroTitle.textContent = target.label;
    if (activeScan) {
        const phaseLabel = activeScan.phase_label ? ` | ${activeScan.phase_label}` : "";
        refs.heroSubtitle.textContent = `${target.root_path} | ${engineLabel(activeScan.engine)} | ${sizeStrategyLabel(activeScan.size_strategy)}${phaseLabel} | \u5df2\u626b ${formatCount(activeScan.processed_entry_count)} \u9879 / ${formatBytes(activeScan.scanned_size_bytes)}`;
    } else {
        const nextRun = target.next_run_at ? `，下次计划 ${formatDate(target.next_run_at)}` : "";
        refs.heroSubtitle.textContent = `${target.root_path} · ${scheduleLabel(target)} · ${sizeStrategyLabel(target.size_strategy)}${nextRun}`;
    }
    renderMetrics();
}

function renderMetrics() {
    const target = selectedTarget();
    const scan = selectedCompletedScan();
    const activeScan = selectedActiveScan();
    const cards = [
        {
            label: activeScan ? "扫描中已累计" : "最近总容量",
            value: activeScan ? formatBytes(activeScan.scanned_size_bytes || 0) : target ? formatBytes(target.last_scan_size_bytes || 0) : "--",
            caption: activeScan ? `当前已扫 ${formatCount(activeScan.processed_file_count)} 个文件` : target ? target.root_path : "添加目标后开始记录",
        },
        {
            label: activeScan ? "当前扫描时长" : "最近扫描",
            value: activeScan ? formatDuration(activeScan.started_at) : target && target.latest_completed_at ? formatDate(target.latest_completed_at) : "--",
            caption: activeScan ? `目录 ${formatCount(activeScan.processed_dir_count)} · 跳过 ${formatCount(activeScan.skipped_entries)}` : target ? scheduleLabel(target) : "支持手动与定时",
        },
        {
            label: activeScan ? "\u626b\u63cf\u5f15\u64ce" : "\u626b\u63cf\u6a21\u5f0f",
            value: activeScan ? engineLabel(activeScan.engine) : target ? modeLabel(target) : "--",
            caption: activeScan
                ? `${sizeStrategyLabel(activeScan.size_strategy)} | ${activeScan.phase_label || "\u5b9e\u65f6\u626b\u63cf"} | \u5df2\u5199\u5165 ${formatCount(activeScan.stored_node_count)} \u4e2a\u8282\u70b9`
                : scan
                    ? `\u5f53\u524d\u67e5\u770b\u7684\u662f\u7b2c ${scan.id} \u6b21\u5feb\u7167 | ${engineLabel(scan.engine)} | ${sizeStrategyLabel(scan.size_strategy)}`
                    : "\u6df1\u5ea6\u6a21\u5f0f / \u5168\u91cf\u6a21\u5f0f",
        },
        {
            label: "历史记录",
            value: `${state.scanList.filter((item) => item.status === "completed").length} 次`,
            caption: activeScan ? "第一次扫描完成后即可切换历史快照" : target ? "可点时间切换不同快照" : "用于观察体积变化",
        },
    ];
    refs.metricsGrid.innerHTML = cards
        .map(
            (card) => `
                <article class="metric-card panel">
                    <p class="metric-label">${escapeHtml(card.label)}</p>
                    <p class="metric-value">${escapeHtml(card.value)}</p>
                    <p class="metric-caption">${escapeHtml(card.caption)}</p>
                </article>
            `,
        )
        .join("");
}

function renderExplorer() {
    const view = state.currentView;
    if (!view) {
        refs.explorerHeader.innerHTML = "";
        refs.tableContainer.className = "table-container empty-state";
        refs.tableContainer.textContent = "还没有数据。先添加目标，再点击“立即扫描”。";
        return;
    }

    const node = view.node;
    const breadcrumbs = view.breadcrumbs || [];
    const depthBadge = node.kind === "dir"
        ? `<span class="small-tag warn">${node.is_truncated ? "已截断，未保存更深层" : `包含 ${node.child_count} 个直接子项`}</span>`
        : '<span class="small-tag">文件节点</span>';
    refs.explorerHeader.innerHTML = `
        <div class="path-header">
            <div>
                <p class="eyebrow">Explorer</p>
                <h3>${escapeHtml(node.name)}</h3>
                <p class="path-summary">${escapeHtml(node.path)}</p>
            </div>
            ${depthBadge}
        </div>
        <div class="breadcrumbs">
            ${breadcrumbs
                .map(
                    (item) => `<button class="breadcrumb-button" data-open-path="${escapeHtml(item.path)}">${escapeHtml(item.name)}</button>`,
                )
                .join("")}
        </div>
    `;

    if (!view.children.length) {
        refs.tableContainer.className = "table-container empty-state";
        refs.tableContainer.textContent = node.is_truncated
            ? "这个目录已经到了保存层级的末端，后面的内容被合并进当前目录大小里。"
            : "这个节点下没有可显示的子项。";
        return;
    }

    refs.tableContainer.className = "table-container";
    refs.tableContainer.innerHTML = `
        <table class="data-table">
            <thead>
                <tr>
                    <th>名称</th>
                    <th>大小</th>
                    <th>占比 %</th>
                    <th>修改时间</th>
                    <th>类型</th>
                    <th>操作</th>
                </tr>
            </thead>
            <tbody>
                ${view.children
                    .map((child) => {
                        const share = node.size_bytes ? child.size_bytes / node.size_bytes : 0;
                        return `
                            <tr>
                                <td>
                                    <div class="name-cell">
                                        <div class="name-main">
                                            <span class="kind-dot ${child.kind === "file" ? "file" : ""}"></span>
                                            <strong>${escapeHtml(child.name)}</strong>
                                            ${child.is_truncated ? '<span class="small-tag warn">截断</span>' : ""}
                                        </div>
                                        <span class="small-meta">${escapeHtml(child.path)}</span>
                                    </div>
                                </td>
                                <td>${formatBytes(child.size_bytes)}</td>
                                <td>
                                    <div class="legend">
                                        <div class="share-meter"><div class="share-fill" style="width: ${Math.max(2, share * 100)}%"></div></div>
                                        <span>${formatPercent(share)}</span>
                                    </div>
                                </td>
                                <td>${formatDate(child.modified_time)}</td>
                                <td>${child.kind === "dir" ? "文件夹" : "文件"}</td>
                                <td><button class="row-button" data-open-path="${escapeHtml(child.path)}">查看</button></td>
                            </tr>
                        `;
                    })
                    .join("")}
            </tbody>
        </table>
    `;
}

function buildChart(history) {
    const points = history.filter((item) => item.size_bytes != null);
    if (!points.length) {
        return '<div class="empty-state">当前路径还没有足够的历史数据。</div>';
    }

    const width = 640;
    const height = 240;
    const padding = { top: 18, right: 18, bottom: 36, left: 54 };
    const maxValue = Math.max(...points.map((item) => Number(item.size_bytes || 0)), 1);
    const minValue = Math.min(...points.map((item) => Number(item.size_bytes || 0)), 0);
    const xStep = points.length === 1 ? 0 : (width - padding.left - padding.right) / (points.length - 1);
    const yRange = Math.max(maxValue - minValue, 1);

    const coordinate = (value, index) => {
        const x = padding.left + xStep * index;
        const ratio = (Number(value) - minValue) / yRange;
        const y = height - padding.bottom - ratio * (height - padding.top - padding.bottom);
        return { x, y };
    };

    const pathData = points
        .map((item, index) => {
            const { x, y } = coordinate(item.size_bytes, index);
            return `${index === 0 ? "M" : "L"}${x} ${y}`;
        })
        .join(" ");

    const yTicks = Array.from({ length: 4 }, (_, index) => {
        const value = maxValue - (yRange / 3) * index;
        const y = padding.top + ((height - padding.top - padding.bottom) / 3) * index;
        return { value, y };
    });

    const labels = points.map((item, index) => {
        const { x } = coordinate(item.size_bytes, index);
        const label = new Date(item.finished_at || item.started_at).toLocaleDateString("zh-CN", {
            month: "2-digit",
            day: "2-digit",
        });
        return `<text class="chart-label" x="${x}" y="${height - 12}" text-anchor="middle">${label}</text>`;
    });

    const circles = points.map((item, index) => {
        const { x, y } = coordinate(item.size_bytes, index);
        return `<circle class="chart-point" cx="${x}" cy="${y}" r="5"><title>${formatDate(item.finished_at || item.started_at)} · ${formatBytes(item.size_bytes)}</title></circle>`;
    });

    return `
        <div class="chart-card">
            <div class="chart-wrap">
                <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="路径大小历史曲线">
                    ${yTicks
                        .map(
                            (tick) => `
                                <line class="chart-grid-line" x1="${padding.left}" y1="${tick.y}" x2="${width - padding.right}" y2="${tick.y}"></line>
                                <text class="chart-axis" x="${padding.left - 10}" y="${tick.y + 4}" text-anchor="end">${escapeHtml(formatBytes(tick.value))}</text>
                            `,
                        )
                        .join("")}
                    <path class="chart-line" d="${pathData}"></path>
                    ${labels.join("")}
                    ${circles.join("")}
                </svg>
            </div>
        </div>
    `;
}

function renderHistory() {
    const view = state.currentView;
    if (!view) {
        refs.historyContainer.className = "history-container empty-state";
        refs.historyContainer.textContent = "扫描后这里会显示当前路径的历史曲线。";
        return;
    }

    const history = view.history || [];
    const previous = history.length > 1 ? history[history.length - 2] : null;
    refs.historyContainer.className = "history-container";
    refs.historyContainer.innerHTML = `
        <div class="legend">
            <div>
                <strong>${escapeHtml(view.node.name)}</strong>
                <p class="path-summary">当前大小 ${formatBytes(view.node.size_bytes)} · ${formatDelta(view.node.size_bytes, previous?.size_bytes ?? null)}</p>
            </div>
            <span class="small-tag">${history.length} 个快照点</span>
        </div>
        ${buildChart(history)}
        <div class="history-list">
            ${history
                .slice()
                .reverse()
                .map((item, index, list) => {
                    const prev = list[index + 1] || null;
                    return `
                        <article class="history-item">
                            <div class="legend">
                                <strong>${formatBytes(item.size_bytes || 0)}</strong>
                                <span class="small-meta">${formatDate(item.finished_at || item.started_at)}</span>
                            </div>
                            <p class="scan-meta">${formatDelta(item.size_bytes || 0, prev?.size_bytes ?? null)}</p>
                        </article>
                    `;
                })
                .join("")}
        </div>
    `;
}

function renderProgressBlock(progress) {
    if (!progress) {
        return '<p class="scan-meta">\u626b\u63cf\u521a\u542f\u52a8\uff0c\u6b63\u5728\u51c6\u5907\u7edf\u8ba1\u4fe1\u606f...</p>';
    }
    const currentPath = progress.current_path ? escapeHtml(progress.current_path) : "\u6b63\u5728\u51c6\u5907...";
    const currentKindLabel = progress.current_kind === "file"
        ? "\u5f53\u524d\u6587\u4ef6"
        : progress.current_kind === "dir"
            ? "\u5f53\u524d\u76ee\u5f55"
            : progress.current_kind === "error"
                ? "\u6700\u8fd1\u8df3\u8fc7(\u6743\u9650/\u9519\u8bef)"
                : progress.current_kind === "skipped"
                    ? "\u6700\u8fd1\u8df3\u8fc7(\u94fe\u63a5/\u91cd\u89e3\u6790)"
                    : "\u5f53\u524d\u8def\u5f84";
    const ratio = Number(progress.progress_ratio);
    const hasRatio = Number.isFinite(ratio) && ratio >= 0 && ratio <= 1;
    const percent = hasRatio ? Math.max(1, Math.min(100, ratio * 100)) : null;
    const phaseLabel = progress.phase_label || "\u5b9e\u65f6\u626b\u63cf";
    const engineText = engineLabel(progress.engine);
    const sizeStrategyText = sizeStrategyLabel(progress.size_strategy);
    const processedRecordCount = Number(progress.processed_record_count || 0);
    const hasRecordEstimate = Number.isFinite(Number(progress.estimated_total_records)) && Number(progress.estimated_total_records) > 0;
    const progressHint = hasRatio
        ? `${phaseLabel} | ${percent.toFixed(percent >= 10 ? 0 : 1)}%`
        : processedRecordCount > 0
            ? `${phaseLabel} | \u5df2\u5904\u7406 ${formatCount(processedRecordCount)} \u6761 MFT \u8bb0\u5f55`
            : `${phaseLabel} | \u6b63\u5728\u6301\u7eed\u8bfb\u53d6 MFT \u8bb0\u5f55`;
    const progressBar = hasRatio
        ? `<div class="scan-progress-bar determinate" style="width: ${percent}%;"></div>`
        : '<div class="scan-progress-bar indeterminate"></div>';
    const recordStat = hasRecordEstimate
        ? `
                <div class="progress-stat">
                    <span>MFT \u8bb0\u5f55</span>
                    <strong>${formatCount(progress.processed_record_count)} / ${formatCount(progress.estimated_total_records)}</strong>
                </div>`
        : processedRecordCount > 0
            ? `
                <div class="progress-stat">
                    <span>MFT \u8bb0\u5f55</span>
                    <strong>${formatCount(processedRecordCount)} \u5df2\u5904\u7406</strong>
                </div>`
        : "";
    const engineNote = progress.engine_note
        ? `<p class="scan-meta">${escapeHtml(progress.engine_note)}</p>`
        : "";
    return `
        <div class="progress-card">
            <div class="progress-head">
                <div>
                    <strong>\u5b9e\u65f6\u626b\u63cf\u8fdb\u5ea6</strong>
                    <p class="scan-meta">${escapeHtml(progressHint)}</p>
                    ${engineNote}
                </div>
                <div class="legend">
                    <span class="small-tag warn">${escapeHtml(engineText)}</span>
                    <span class="small-tag">${escapeHtml(sizeStrategyText)}</span>
                    <span class="small-tag running">\u5df2\u8fd0\u884c ${formatDuration(progress.started_at)}</span>
                </div>
            </div>
            <div class="scan-progress" aria-label="\u626b\u63cf\u8fdb\u884c\u4e2d">
                ${progressBar}
            </div>
            <div class="progress-stats">
                ${recordStat}
                <div class="progress-stat">
                    <span>\u5df2\u626b\u9879\u76ee</span>
                    <strong>${formatCount(progress.processed_entry_count)}</strong>
                </div>
                <div class="progress-stat">
                    <span>\u6587\u4ef6</span>
                    <strong>${formatCount(progress.processed_file_count)}</strong>
                </div>
                <div class="progress-stat">
                    <span>\u76ee\u5f55</span>
                    <strong>${formatCount(progress.processed_dir_count)}</strong>
                </div>
                <div class="progress-stat">
                    <span>\u7d2f\u8ba1\u5927\u5c0f</span>
                    <strong>${formatBytes(progress.scanned_size_bytes)}</strong>
                </div>
                <div class="progress-stat">
                    <span>\u5df2\u5199\u5165\u8282\u70b9</span>
                    <strong>${formatCount(progress.stored_node_count)}</strong>
                </div>
                <div class="progress-stat">
                    <span>\u8df3\u8fc7\u9879</span>
                    <strong>${formatCount(progress.skipped_entries)}</strong>
                </div>
            </div>
            <div class="progress-current-path">
                <span>${currentKindLabel}</span>
                <strong>${currentPath}</strong>
            </div>
        </div>
    `;
}

function renderScanList() {
    const target = selectedTarget();
    if (!state.scanList.length) {
        refs.scanList.className = "scan-list empty-state";
        refs.scanList.textContent = "暂无扫描记录。";
        return;
    }
    refs.scanList.className = "scan-list";
    refs.scanList.innerHTML = state.scanList
        .map((scan) => {
            const progress = progressForScan(scan);
            const hasLiveProgress = Boolean(progress);
            const isRunning = hasLiveProgress;
            const isBusy = isBusyScanStatus(scan.status);
            const isStaleRun = !hasLiveProgress && isBusy;
            const isSwitchable = scan.status === "completed";
            const isDeletable = !isBusy;
            const statusClass = scan.status === "completed"
                ? "success"
                : scan.status === "failed"
                    ? "danger"
                    : scan.status === "canceled" || isStaleRun
                        ? "warn"
                        : "running";
            const sizeLabel = isRunning && progress
                ? `${formatBytes(progress.scanned_size_bytes)} | ${scanModeLabel(scan)} | ${engineLabel(progress.engine || scan.engine)} | ${sizeStrategyLabel(progress.size_strategy || scan.size_strategy)}`
                : `${formatBytes(scan.total_size_bytes || 0)} | ${scanModeLabel(scan)} | ${engineLabel(scan.engine)} | ${sizeStrategyLabel(scan.size_strategy)}`;
            return `
                <article class="scan-item ${scan.id === state.selectedScanId ? "active" : ""}">
                    <div class="legend">
                        <strong>#${scan.id}</strong>
                        <span class="small-tag ${statusClass}">${escapeHtml(isStaleRun ? "stale" : scan.status)}</span>
                    </div>
                    <p class="scan-meta">${formatDate(scan.finished_at || scan.started_at)}</p>
                    <p class="scan-meta">${sizeLabel}</p>
                    ${isRunning ? renderProgressBlock(progress || target?.active_scan || null) : ""}
                    ${isStaleRun ? `<p class="scan-meta">??????????????????????????????????????</p>` : ""}
                    ${scan.error_message ? `<p class="error-message">${escapeHtml(scan.error_message)}</p>` : ""}
                    <div class="scan-item-actions">
                        ${isRunning ? `<button class="scan-row-button" data-stop-scan="${target?.id || scan.target_id}" ${progress?.cancel_requested ? "disabled" : ""}>${progress?.cancel_requested ? "\u6b63\u5728\u505c\u6b62..." : "\u4e2d\u65ad\u8fd9\u6b21\u626b\u63cf"}</button>` : ""}
                        <button class="scan-row-button" data-open-scan="${scan.id}" ${isSwitchable ? "" : "disabled"}>${isSwitchable ? "\u5207\u6362\u5230\u8fd9\u4e2a\u5feb\u7167" : scan.status === "canceled" ? "\u5df2\u4e2d\u65ad\uff0c\u4e0d\u80fd\u67e5\u770b" : "\u626b\u63cf\u4e2d\u6682\u4e0d\u53ef\u67e5\u770b"}</button>
                        ${isDeletable ? `<button class="scan-row-button danger" data-delete-scan="${scan.id}">\u5220\u9664\u5feb\u7167</button>` : ""}
                    </div>
                </article>
            `;
        })
        .join("");
}

async function loadView(scanId, path = null) {
    if (!scanId) {
        state.currentView = null;
        state.currentPath = null;
        renderExplorer();
        renderHistory();
        return;
    }
    const query = path ? `?path=${encodeURIComponent(path)}` : "";
    try {
        state.currentView = await api(`/api/scans/${scanId}/view${query}`);
    } catch (error) {
        if (path) {
            state.currentView = await api(`/api/scans/${scanId}/view`);
        } else {
            throw error;
        }
    }
    state.selectedScanId = scanId;
    state.currentPath = state.currentView.node.path;
    renderExplorer();
    renderHistory();
    renderMetrics();
    renderScanList();
}

function renderPendingFirstScan(target) {
    refs.explorerHeader.innerHTML = `
        <div class="path-header">
            <div>
                <p class="eyebrow">Explorer</p>
                <h3>${escapeHtml(target.label)}</h3>
                <p class="path-summary">第一份快照正在生成，完成后这里会出现可展开的目录结构。</p>
            </div>
        </div>
    `;
    refs.tableContainer.className = "table-container empty-state";
    refs.tableContainer.textContent = "第一次扫描进行中，先看右侧实时进度。扫描完成后这里会自动刷新。";
    refs.historyContainer.className = "history-container empty-state";
    refs.historyContainer.textContent = "第一份快照还没完成，暂时没有历史趋势。";
}

async function loadTargetDetails() {
    const target = selectedTarget();
    if (!target) {
        state.scanList = [];
        state.currentView = null;
        renderHero();
        renderExplorer();
        renderHistory();
        renderScanList();
        return;
    }

    state.scanList = await api(`/api/targets/${target.id}/scans?limit=16`);
    renderHero();
    renderScanList();

    const completedScan = state.scanList.find((scan) => scan.status === "completed");
    const desiredScanId = state.selectedScanId && state.scanList.some((scan) => scan.id === state.selectedScanId && scan.status === "completed")
        ? state.selectedScanId
        : completedScan?.id || null;

    if (!desiredScanId) {
        state.currentView = null;
        state.currentPath = null;
        if (target.active_scan) {
            renderPendingFirstScan(target);
        } else {
            renderExplorer();
            renderHistory();
        }
        return;
    }
    await loadView(desiredScanId, state.currentPath);
}

async function loadTargets({ preserveSelection = true } = {}) {
    const targets = await api("/api/targets");
    state.targets = targets;
    if (!preserveSelection || !state.selectedTargetId || !targets.some((target) => target.id === state.selectedTargetId)) {
        state.selectedTargetId = targets[0]?.id || null;
        state.selectedScanId = null;
        state.currentPath = null;
    }
    renderTargets();
    renderHero();
    await loadTargetDetails();
}

async function stopScan(targetId) {
    try {
        await api(`/api/targets/${targetId}/stop`, { method: "POST" });
        showToast("\u5df2\u53d1\u9001\u4e2d\u65ad\u8bf7\u6c42\uff0c\u6b63\u5728\u505c\u6b62\u626b\u63cf\u3002", "info");
        await loadTargets();
    } catch (error) {
        showToast(error.message, "error");
    }
}

async function runScan(targetId) {
    try {
        await api(`/api/targets/${targetId}/scan`, { method: "POST" });
        showToast("扫描任务已加入队列。", "info");
        await loadTargets();
    } catch (error) {
        showToast(error.message, "error");
    }
}

async function deleteTarget(targetId) {
    const target = state.targets.find((item) => item.id === targetId);
    const targetLabel = target?.label || `#${targetId}`;
    const confirmed = window.confirm(`\u786e\u5b9a\u5220\u9664\u626b\u63cf\u76ee\u6807\u300c${targetLabel}\u300d\u5417\uff1f\u76f8\u5173\u5feb\u7167\u4e5f\u4f1a\u4e00\u8d77\u5220\u6389\uff0c\u800c\u4e14\u65e0\u6cd5\u6062\u590d\u3002`);
    if (!confirmed) {
        return;
    }
    try {
        await api(`/api/targets/${targetId}`, { method: "DELETE" });
        if (state.selectedTargetId === targetId) {
            state.selectedTargetId = null;
            state.selectedScanId = null;
            state.currentPath = null;
            state.currentView = null;
        }
        showToast("\u626b\u63cf\u76ee\u6807\u5df2\u5220\u9664\u3002", "info");
        await loadTargets({ preserveSelection: false });
    } catch (error) {
        if (error.message.includes("Target not found")) {
            state.selectedTargetId = null;
            state.selectedScanId = null;
            state.currentPath = null;
            state.currentView = null;
            showToast("\u8fd9\u4e2a\u626b\u63cf\u76ee\u6807\u5df2\u4e0d\u5b58\u5728\uff0c\u5df2\u4e3a\u4f60\u5237\u65b0\u5217\u8868\u3002", "info");
            await loadTargets({ preserveSelection: false });
            return;
        }
        const message = error.message.includes("currently scanning")
            ? "\u626b\u63cf\u4e2d\u7684\u76ee\u6807\u4e0d\u80fd\u5220\u9664\u3002"
            : error.message;
        showToast(message, "error");
    }
}

async function deleteScan(scanId) {
    const confirmed = window.confirm("\u786e\u5b9a\u5220\u9664\u8fd9\u4e2a\u5feb\u7167\u5417\uff1f\u5220\u9664\u540e\u65e0\u6cd5\u6062\u590d\u3002");
    if (!confirmed) {
        return;
    }
    try {
        await api(`/api/scans/${scanId}`, { method: "DELETE" });
        if (state.selectedScanId === scanId) {
            state.selectedScanId = null;
        }
        showToast("\u5feb\u7167\u5df2\u5220\u9664\u3002", "info");
        await loadTargets();
    } catch (error) {
        if (error.message.includes("Scan not found")) {
            if (state.selectedScanId === scanId) {
                state.selectedScanId = null;
                state.currentPath = null;
                state.currentView = null;
            }
            showToast("\u8fd9\u4efd\u5feb\u7167\u5df2\u4e0d\u5b58\u5728\uff0c\u5df2\u4e3a\u4f60\u5237\u65b0\u5217\u8868\u3002", "info");
            await loadTargets();
            return;
        }
        const message = error.message.includes("currently running")
            ? "\u6b63\u5728\u8fd0\u884c\u7684\u626b\u63cf\u4e0d\u80fd\u5220\u9664\u3002"
            : error.message;
        showToast(message, "error");
    }
}

function openDialog(mode) {
    const target = selectedTarget();
    state.formMode = mode;
    refs.dialogTitle.textContent = mode === "edit" ? "编辑扫描目标" : "添加扫描目标";
    if (mode === "edit" && target) {
        refs.labelInput.value = target.label || "";
        refs.rootPathInput.value = target.root_path || "";
        refs.scanModeInput.value = target.scan_mode || "depth";
        refs.sizeStrategyInput.value = target.size_strategy || "allocated";
        refs.maxDepthInput.value = target.max_depth || 6;
        refs.scheduleTypeInput.value = target.schedule_type || "manual";
        refs.intervalHoursInput.value = target.interval_hours || 1;
        refs.dailyTimeInput.value = target.daily_time || "09:00";
        refs.enabledInput.checked = Boolean(target.enabled);
    } else {
        refs.form.reset();
        refs.scanModeInput.value = "depth";
        refs.sizeStrategyInput.value = "logical";
        refs.maxDepthInput.value = 6;
        refs.scheduleTypeInput.value = "manual";
        refs.intervalHoursInput.value = 1;
        refs.dailyTimeInput.value = "09:00";
        refs.enabledInput.checked = true;
    }
    setDialogVisibility();
    refs.dialog.showModal();
}

function closeDialog() {
    refs.dialog.close();
}

function formPayload() {
    return {
        label: refs.labelInput.value.trim() || null,
        root_path: refs.rootPathInput.value.trim(),
        scan_mode: refs.scanModeInput.value,
        size_strategy: refs.sizeStrategyInput.value,
        max_depth: Number(refs.maxDepthInput.value || 6),
        schedule_type: refs.scheduleTypeInput.value,
        interval_hours: refs.scheduleTypeInput.value === "hourly" ? Number(refs.intervalHoursInput.value || 1) : null,
        daily_time: refs.scheduleTypeInput.value === "daily" ? refs.dailyTimeInput.value : null,
        enabled: refs.enabledInput.checked,
    };
}

async function submitForm(event) {
    event.preventDefault();
    const target = selectedTarget();
    const payload = formPayload();
    const url = state.formMode === "edit" && target
        ? `/api/targets/${target.id}`
        : "/api/targets";
    const method = state.formMode === "edit" ? "PUT" : "POST";
    try {
        const result = await api(url, {
            method,
            body: JSON.stringify(payload),
        });
        closeDialog();
        showToast(state.formMode === "edit" ? "目标已更新。" : "目标已创建。", "info");
        state.selectedTargetId = result.id;
        state.selectedScanId = null;
        state.currentPath = null;
        await loadTargets();
    } catch (error) {
        showToast(error.message, "error");
    }
}

function bindEvents() {
    refs.addTargetButton.addEventListener("click", () => openDialog("create"));
    refs.editTargetButton.addEventListener("click", () => openDialog("edit"));
    refs.refreshButton.addEventListener("click", () => loadTargets());
    refs.scanNowButton.addEventListener("click", () => {
        if (!state.selectedTargetId) {
            return;
        }
        if (selectedActiveScan()) {
            stopScan(state.selectedTargetId);
            return;
        }
        runScan(state.selectedTargetId);
    });
    refs.closeDialogButton.addEventListener("click", closeDialog);
    refs.cancelDialogButton.addEventListener("click", closeDialog);
    refs.form.addEventListener("submit", submitForm);
    refs.scanModeInput.addEventListener("change", setDialogVisibility);
    refs.scheduleTypeInput.addEventListener("change", setDialogVisibility);

    refs.targetList.addEventListener("click", async (event) => {
        const button = event.target.closest("button[data-action]");
        const card = event.target.closest("[data-target-id]");
        if (button) {
            const targetId = Number(button.dataset.targetId);
            if (button.dataset.action === "scan") {
                await runScan(targetId);
                return;
            }
            if (button.dataset.action === "stop") {
                await stopScan(targetId);
                return;
            }
            if (button.dataset.action === "delete") {
                await deleteTarget(targetId);
                return;
            }
            state.selectedTargetId = targetId;
            state.selectedScanId = null;
            state.currentPath = null;
            renderTargets();
            await loadTargetDetails();
            return;
        }
        if (card) {
            state.selectedTargetId = Number(card.dataset.targetId);
            state.selectedScanId = null;
            state.currentPath = null;
            renderTargets();
            await loadTargetDetails();
        }
    });

    refs.tableContainer.addEventListener("click", async (event) => {
        const button = event.target.closest("[data-open-path]");
        if (!button || !state.selectedScanId) {
            return;
        }
        const path = button.dataset.openPath;
        await loadView(state.selectedScanId, path);
    });

    refs.explorerHeader.addEventListener("click", async (event) => {
        const button = event.target.closest("[data-open-path]");
        if (!button || !state.selectedScanId) {
            return;
        }
        const path = button.dataset.openPath;
        await loadView(state.selectedScanId, path);
    });

    refs.scanList.addEventListener("click", async (event) => {
        const stopButton = event.target.closest("[data-stop-scan]");
        if (stopButton) {
            await stopScan(Number(stopButton.dataset.stopScan));
            return;
        }
        const deleteButton = event.target.closest("[data-delete-scan]");
        if (deleteButton) {
            await deleteScan(Number(deleteButton.dataset.deleteScan));
            return;
        }
        const button = event.target.closest("[data-open-scan]");
        if (!button || button.disabled) {
            return;
        }
        state.selectedScanId = Number(button.dataset.openScan);
        await loadView(state.selectedScanId, state.currentPath);
    });
}

async function boot() {
    bindEvents();
    setDialogVisibility();
    try {
        await loadTargets({ preserveSelection: false });
    } catch (error) {
        showToast(error.message, "error");
    }
    window.setInterval(async () => {
        const shouldRefresh = state.targets.some((target) => target.is_scanning) || state.scanList.some((scan) => ["running", "starting", "queued", "stopping"].includes(scan.status));
        if (!shouldRefresh) {
            return;
        }
        try {
            await loadTargets();
        } catch (error) {
            showToast(error.message, "error");
        }
    }, 2000);
    window.setInterval(async () => {
        try {
            await loadTargets();
        } catch (error) {
            showToast(error.message, "error");
        }
    }, 30000);
}

boot();
