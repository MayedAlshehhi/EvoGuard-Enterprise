import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import "./App.css";

import logoIcon from "./assets/logo-icon.png";

import {
  MapContainer,
  TileLayer,
  Marker,
  Popup,
  Polyline,
  CircleMarker,
} from "react-leaflet";

import L from "leaflet";
import "leaflet/dist/leaflet.css";
import { io } from "socket.io-client";

import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
} from "recharts";

const API_BASE_URL =
  (process.env.REACT_APP_API_BASE_URL || "http://127.0.0.1:5000").replace(
    /\/$/,
    ""
  );

const apiUrl = (path) => `${API_BASE_URL}${path}`;

const UAE_TARGET = [25.2048, 55.2708];

const attackIcon = new L.Icon({
  iconUrl: "https://cdn-icons-png.flaticon.com/512/565/565547.png",
  iconSize: [30, 30],
});

const navItems = [
  { page: "Dashboard", icon: "01" },
  { page: "Threat Intel", icon: "02" },
  { page: "Attack Map", icon: "03" },
  { page: "Simulation", icon: "04" },
  { page: "Reports", icon: "05" },
  { page: "Settings", icon: "06" },
];

const sourcePool = [
  { country: "Russia", coords: [55.7558, 37.6173], attack: "DDoS traffic" },
  { country: "China", coords: [39.9042, 116.4074], attack: "Probe scans" },
  { country: "USA", coords: [38.9072, -77.0369], attack: "R2L attempts" },
  { country: "Iran", coords: [35.6892, 51.389], attack: "U2R attempts" },
  { country: "Germany", coords: [52.52, 13.405], attack: "Credential attack" },
  { country: "Brazil", coords: [-15.7939, -47.8828], attack: "Botnet traffic" },
  { country: "India", coords: [28.6139, 77.209], attack: "Scanning activity" },
  { country: "North Korea", coords: [39.0392, 125.7625], attack: "Intrusion attempt" },
];

const attackProfiles = {
  dos: {
    chartName: "DoS",
    category: "DoS / DDoS",
    label: "Distributed Denial of Service",
    riskLevel: "Critical",
    score: [84, 98],
    severity: "critical",
    explanation:
      "High-volume traffic is attempting to exhaust service availability and overwhelm protected infrastructure.",
    actions: [
      "Block high-volume source IP addresses.",
      "Apply rate limiting on exposed services.",
      "Enable DDoS mitigation rules.",
      "Execute autonomous service containment workflow.",
    ],
  },
  probe: {
    chartName: "Probe",
    category: "Probe / Scan",
    label: "Reconnaissance Scan",
    riskLevel: "High",
    score: [62, 78],
    severity: "high",
    explanation:
      "Reconnaissance behavior suggests an attacker is mapping services, ports, and exposed network surfaces.",
    actions: [
      "Throttle scanning source addresses.",
      "Review exposed service inventory.",
      "Increase monitoring on scanned ports.",
      "Add source IP to the watchlist.",
    ],
  },
  r2l: {
    chartName: "R2L",
    category: "R2L Unauthorized Access",
    label: "Remote To Local Attempt",
    riskLevel: "High",
    score: [70, 86],
    severity: "high",
    explanation:
      "Remote access behavior indicates a possible attempt to gain unauthorized local account access.",
    actions: [
      "Review authentication logs.",
      "Force password reset for targeted accounts.",
      "Temporarily restrict suspicious remote sessions.",
      "Execute autonomous identity containment workflow.",
    ],
  },
  u2r: {
    chartName: "U2R",
    category: "U2R Privilege Escalation",
    label: "User To Root Attempt",
    riskLevel: "Critical",
    score: [88, 99],
    severity: "critical",
    explanation:
      "Privilege escalation behavior suggests an attacker may be attempting to gain administrator-level control.",
    actions: [
      "Isolate suspicious endpoint.",
      "Terminate elevated suspicious processes.",
      "Collect forensic evidence.",
      "Execute autonomous privilege containment workflow.",
    ],
  },
  normal: {
    chartName: "Normal",
    category: "Normal Traffic",
    label: "Benign Network Activity",
    riskLevel: "Low",
    score: [5, 18],
    severity: "low",
    explanation:
      "Traffic pattern appears legitimate and does not currently require defensive action.",
    actions: [
      "Continue passive monitoring.",
      "Store baseline traffic pattern.",
      "No autonomous containment required.",
    ],
  },
};

const liveTestProfiles = {
  dos: {
    label: "DoS / DDoS",
    country: "Russia",
    ip: "203.0.113.77",
    sourceActivity: "High-volume TCP flood targeting public service",
  },
  probe: {
    label: "Probe / Scan",
    country: "China",
    ip: "198.51.100.23",
    sourceActivity: "Repeated port scanning across exposed services",
  },
  r2l: {
    label: "R2L Access",
    country: "Germany",
    ip: "198.51.100.44",
    sourceActivity: "Repeated suspicious login attempts",
  },
  u2r: {
    label: "U2R Escalation",
    country: "Iran",
    ip: "203.0.113.91",
    sourceActivity: "Possible privilege escalation sequence",
  },
  normal: {
    label: "Normal Traffic",
    country: "UAE",
    ip: "192.0.2.10",
    sourceActivity: "Normal baseline network traffic",
  },
};

const COLORS = ["#ef4444", "#f97316", "#eab308", "#22c55e", "#00ffe0"];

const initialSimStats = {
  total: 0,
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  dos: 0,
  probe: 0,
  r2l: 0,
  u2r: 0,
  normal: 0,
};

const initialWeeklyData = [
  { day: "Mon", attacks: 0 },
  { day: "Tue", attacks: 0 },
  { day: "Wed", attacks: 0 },
  { day: "Thu", attacks: 0 },
  { day: "Fri", attacks: 0 },
];

const randomItem = (items) => items[Math.floor(Math.random() * items.length)];

const randomBetween = ([min, max]) =>
  Math.floor(Math.random() * (max - min + 1)) + min;

const generateIP = () =>
  `${Math.floor(Math.random() * 255)}.${Math.floor(
    Math.random() * 255
  )}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;

const formatBytes = (value = 0) => {
  if (!Number.isFinite(value)) return "0 B";

  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = Math.max(value, 0);
  let unitIndex = 0;

  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }

  const formattedSize = size >= 10 || unitIndex === 0 ? size.toFixed(0) : size.toFixed(1);
  return `${formattedSize} ${units[unitIndex]}`;
};

const prependUniqueById = (items, item, limit = 50) => {
  if (!item?.id) return items.slice(0, limit);
  return [item, ...items.filter((existing) => existing.id !== item.id)].slice(0, limit);
};

const mergeUniqueById = (existingItems, nextItems, limit = 50) => {
  const seen = new Set();

  return [...nextItems, ...existingItems]
    .filter((item) => {
      if (!item?.id || seen.has(item.id)) return false;
      seen.add(item.id);
      return true;
    })
    .slice(0, limit);
};

const getCurrentChartDay = () => {
  const day = new Date().toLocaleDateString("en-US", { weekday: "short" });
  return ["Mon", "Tue", "Wed", "Thu", "Fri"].includes(day) ? day : "Fri";
};


function getSourceCoords(country) {
  const source = sourcePool.find(
    (item) => item.country.toLowerCase() === String(country || "").toLowerCase()
  );

  return source?.coords || [52.52, 13.405];
}

function buildLiveMapEvent(item) {
  const timestamp = item.timestamp || new Date().toLocaleString();

  return {
    id: `LIVE-${item.id}`,
    type: item.event_source || "live",
    ip: item.ip || item.source_ip || "Unknown",
    country: item.country || item.source_country || "External",
    from: item.route_from || getSourceCoords(item.country || item.source_country),
    to: item.route_to || UAE_TARGET,
    time: timestamp.split(" ").slice(-1)[0],
    timestamp,
    attack_category: item.attack_category || "Security Event",
    attack_label: item.attack_label || "Unknown",
    risk_level: item.risk_level || "Medium",
    risk_score: item.risk_score ?? 0,
    explanation: item.explanation || "Live event received by EvoGuard.",
    recommended_actions: item.recommended_actions || [],
    response_actions: item.response_actions || [],
    ai_response: item.ai_response || null,
    response_mode: item.response_mode || "Autonomous AI Response",
    response_confidence: item.response_confidence ?? 0,
    source_activity: item.source_activity || "Live backend event",
    event_source: item.event_source || "live",
  };
}
function buildAttackEvent(type, apiData = null) {
  const profile = attackProfiles[type] || attackProfiles.normal;
  const source = randomItem(sourcePool);
  const now = new Date();

  return {
    id: `EVG-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
    type,
    ip: generateIP(),
    country: source.country,
    from: source.coords,
    to: UAE_TARGET,
    time: now.toLocaleTimeString(),
    timestamp: now.toLocaleString(),
    attack_category: apiData?.attack_category || profile.category,
    attack_label: apiData?.attack_label || profile.label,
    risk_level: apiData?.risk_level || profile.riskLevel,
    risk_score: apiData?.risk_score || randomBetween(profile.score),
    explanation: apiData?.explanation || profile.explanation,
    recommended_actions: apiData?.recommended_actions || profile.actions,
    response_mode: apiData?.response_mode || "Autonomous AI response simulation",
    response_confidence: apiData?.response_confidence ?? randomBetween([72, 96]),
    source_activity: apiData?.source_activity || source.attack,
  };
}

const ThreatMap = React.memo(function ThreatMap({
  height = "230px",
  liveAttacks = [],
  emptyTitle = "No active attacks",
  emptyMessage = "Run a simulation to generate live routes.",
  selectedAttackId = "",
  onSelectAttack,
}) {

  const hasLiveAttacks = liveAttacks.length > 0;
    return (
      <div className="threat-map-wrap" style={{ height }}>
        {!hasLiveAttacks && (
          <div className="map-empty-state">
            <strong>{emptyTitle}</strong>
            <span>{emptyMessage}</span>
          </div>
        )}

        <MapContainer
      center={UAE_TARGET}
      zoom={2}
      zoomAnimation={false}
      fadeAnimation={false}
      markerZoomAnimation={false}
      style={{ height: "100%", width: "100%", borderRadius: "12px" }}
      preferCanvas={true}
      zoomControl={false}
      attributionControl={false}
    >
      <TileLayer
        attribution="&copy; CartoDB"
        url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
      />


      {liveAttacks.map((event) => (
        <React.Fragment key={event.id}>
          <Polyline
            positions={[event.from, event.to]}
            className="neon-attack-line"
            pathOptions={{
              color: event.risk_level === "Critical" ? "#ff2bd6" : "#00ffe0",
              weight: selectedAttackId === event.id ? 5 : event.risk_level === "Critical" ? 4 : 3,
              opacity: selectedAttackId === event.id ? 1 : 0.78,
            }}
          />

          <CircleMarker
            center={event.from}
            radius={selectedAttackId === event.id ? 12 : 9}
            className="pulse-marker"
            eventHandlers={{
              click: () => onSelectAttack?.(event.id),
            }}
            pathOptions={{
              color: event.risk_level === "Critical" ? "#ff2bd6" : "#00ffe0",
              fillColor:
                event.risk_level === "Critical" ? "#ff2bd6" : "#00ffe0",
              fillOpacity: 1,
            }}
          >
            <Popup>
              <strong>Live Attack</strong>
              <br />
              Country: {event.country}
              <br />
              IP: {event.ip}
              <br />
              Type: {event.attack_category}
              <br />
              Risk: {event.risk_level}
            </Popup>
          </CircleMarker>
        </React.Fragment>
      ))}

      <Marker position={UAE_TARGET} icon={attackIcon}>
        <Popup>
          <strong>Protected Target</strong>
          <br />
          UAE Government Network
        </Popup>
      </Marker>
    </MapContainer>
  </div>
);
});

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(
    localStorage.getItem("evoguard_logged_in") === "true"
  );
  const [loginForm, setLoginForm] = useState({ username: "", password: "" });
  const [loginError, setLoginError] = useState("");
  const [currentUser, setCurrentUser] = useState(
    JSON.parse(localStorage.getItem("evoguard_user") || "null")
  );
  const [activePage, setActivePage] = useState("Dashboard");

  const [searchTerm, setSearchTerm] = useState("");
  const [searchResults, setSearchResults] = useState([]);
  const [connectionError, setConnectionError] = useState("");
  const [realtimeStatus, setRealtimeStatus] = useState("Polling Fallback");
  const [selectedMapAttackId, setSelectedMapAttackId] = useState("");
  const [liveTestForm, setLiveTestForm] = useState({
    attackType: "dos",
    country: liveTestProfiles.dos.country,
    ip: liveTestProfiles.dos.ip,
    sourceActivity: liveTestProfiles.dos.sourceActivity,
  });
  const [liveTestStatus, setLiveTestStatus] = useState("");
  const [liveTestBusy, setLiveTestBusy] = useState(false);

  const [stats, setStats] = useState(null);
  const [deviceStats, setDeviceStats] = useState(null);
  const [attack, setAttack] = useState(null);
  const [history, setHistory] = useState([]);
  const [aiResponses, setAiResponses] = useState([]);
  const [threatIntel, setThreatIntel] = useState(null);
  const [simulationHistory, setSimulationHistory] = useState([]);
  const [weeklyData, setWeeklyData] = useState(initialWeeklyData);
  const [simStats, setSimStats] = useState(initialSimStats);

  const [chatQuestion, setChatQuestion] = useState("");
  const [chatAnswer, setChatAnswer] = useState("");
  const [toast, setToast] = useState(null);
  const [socAlert, setSocAlert] = useState(null);
  const [liveMapAttacks, setLiveMapAttacks] = useState([]);
  const [autoSimulation, setAutoSimulation] = useState(false);
  const [voiceEnabled, setVoiceEnabled] = useState(true);

  const [liveThreats, setLiveThreats] = useState([
    "[READY] No active threats. Simulation engine is standing by.",
  ]);
  const [activityFeed, setActivityFeed] = useState([
    "[SYSTEM] EvoGuard AI engine initialized.",
    "[AI] Threat monitoring active.",
  ]);
  const [socLogs, setSocLogs] = useState([
    "[BOOT] EvoGuard AI defense terminal initialized.",
    "[AI] Model loaded and ready.",
    "[DB] SQLite threat logging connected.",
  ]);

  const welcomeSpoken = useRef(false);
  const socketRef = useRef(null);

  const attackData = useMemo(
    () => [
      { name: "DoS", value: simStats.dos },
      { name: "Probe", value: simStats.probe },
      { name: "R2L", value: simStats.r2l },
      { name: "U2R", value: simStats.u2r },
      { name: "Normal", value: simStats.normal },
    ],
    [simStats]
  );

  const dashboardAttackData = useMemo(() => {
    const counts = stats?.category_counts;

    if (!counts) return attackData;

    return [
      { name: "DoS", value: counts.dos || 0 },
      { name: "Probe", value: counts.probe || 0 },
      { name: "R2L", value: counts.r2l || 0 },
      { name: "U2R", value: counts.u2r || 0 },
      { name: "Normal", value: counts.normal || 0 },
    ];
  }, [stats, attackData]);

  const dashboardWeeklyData = useMemo(
    () => (stats?.weekly_trend?.length ? stats.weekly_trend : weeklyData),
    [stats, weeklyData]
  );

  const liveDashboardAttacks = useMemo(
    () => history.slice(0, 10).map(buildLiveMapEvent),
    [history]
  );

  const liveMapSourceSummary = useMemo(() => {
    const summary = liveDashboardAttacks.reduce((acc, event) => {
      const key = event.country || "External";
      const current = acc[key] || {
        country: key,
        count: 0,
        maxRiskScore: 0,
        risk_level: "Low",
        latest: event,
        categories: new Set(),
      };

      current.count += 1;
      current.categories.add(event.attack_category);

      if ((event.risk_score || 0) >= current.maxRiskScore) {
        current.maxRiskScore = event.risk_score || 0;
        current.risk_level = event.risk_level || current.risk_level;
        current.latest = event;
      }

      acc[key] = current;
      return acc;
    }, {});

    return Object.values(summary)
      .map((source) => ({
        ...source,
        categories: Array.from(source.categories).join(", "),
      }))
      .sort((a, b) => b.maxRiskScore - a.maxRiskScore || b.count - a.count);
  }, [liveDashboardAttacks]);

  const mapMetrics = useMemo(() => {
    const highImpact = liveDashboardAttacks.filter((event) =>
      ["Critical", "High"].includes(event.risk_level)
    ).length;
    const countries = new Set(liveDashboardAttacks.map((event) => event.country));
    const highestRisk = liveDashboardAttacks.reduce(
      (max, event) => Math.max(max, event.risk_score || 0),
      0
    );

    return {
      totalRoutes: liveDashboardAttacks.length,
      activeSources: countries.size,
      highImpact,
      highestRisk,
    };
  }, [liveDashboardAttacks]);

  const selectedMapIncident = useMemo(
    () =>
      liveDashboardAttacks.find((event) => event.id === selectedMapAttackId) ||
      liveDashboardAttacks[0] ||
      null,
    [liveDashboardAttacks, selectedMapAttackId]
  );

  const searchIndex = useMemo(
  () => [
    { type: "Page", title: "Dashboard", subtitle: "Real-time monitoring", page: "Dashboard" },
    { type: "Page", title: "Threat Intel", subtitle: "Threat intelligence overview", page: "Threat Intel" },
    { type: "Page", title: "Attack Map", subtitle: "Live attack origin tracking", page: "Attack Map" },
    { type: "Page", title: "Simulation", subtitle: "Run attack tests", page: "Simulation" },
    { type: "Page", title: "Reports", subtitle: "Security reports center", page: "Reports" },
    { type: "Page", title: "Settings", subtitle: "System configuration", page: "Settings" },

    ...history.map((item) => ({
      type: "Incident",
      title: item.attack_category,
      subtitle: `${item.attack_label} | ${item.risk_level} | ${item.timestamp}`,
      page: "Dashboard",
    })),

    ...simulationHistory.map((item) => ({
      type: "Simulation Event",
      title: item.attack_category,
      subtitle: `${item.attack_label} | ${item.risk_level} | ${item.timestamp}`,
      page: "Simulation",
    })),

    ...liveDashboardAttacks.map((item) => ({
      type: "Live Source",
      title: item.country,
      subtitle: `${item.attack_category} | ${item.ip} | ${item.risk_level}`,
      page: "Attack Map",
    })),

    ...aiResponses.map((item) => ({
      type: "AI Response",
      title: item.action_name,
      subtitle: `${item.status} | ${item.execution_stage} | ${item.confidence || 0}% confidence`,
      page: "Dashboard",
    })),

    ...(threatIntel?.iocs || []).map((item) => ({
      type: "IOC",
      title: item.indicator_value,
      subtitle: `${item.indicator_type} | ${item.reputation} | ${item.confidence || 0}% confidence`,
      page: "Threat Intel",
    })),

    ...(threatIntel?.mitre_techniques || []).map((item) => ({
      type: "MITRE",
      title: item.technique,
      subtitle: `${item.tactic} | ${item.events} events`,
      page: "Threat Intel",
    })),

    ...liveMapAttacks.map((item) => ({
      type: "Simulation Route",
      title: item.country,
      subtitle: `${item.attack_category} | ${item.ip} | ${item.risk_level}`,
      page: "Simulation",
    })),

    ...(stats?.latest_attack
      ? [
          {
            type: "Latest Live Attack",
            title: stats.latest_attack.attack_category,
            subtitle: `${stats.latest_attack.attack_label} | ${stats.latest_attack.risk_score}/100 | ${stats.latest_attack.risk_level}`,
            page: "Dashboard",
          },
        ]
      : []),
  ],
  [
    history,
    liveMapAttacks,
    stats,
    simulationHistory,
    liveDashboardAttacks,
    aiResponses,
    threatIntel,
  ]
);

const handleSearch = useCallback(async () => {
  const query = searchTerm.trim().toLowerCase();

  if (!query) {
    setSearchResults([]);
    return;
  }

  const localResults = searchIndex
    .filter((item) =>
      `${item.type} ${item.title} ${item.subtitle}`
        .toLowerCase()
        .includes(query)
    )
    .slice(0, 8);

  try {
    const response = await fetch(
      apiUrl(`/search?q=${encodeURIComponent(query)}`)
    );

    if (!response.ok) {
      throw new Error("Search request failed");
    }

    const data = await response.json();
    const backendResults = (data.results || []).map((item) => ({
      type: item.type || "Incident",
      title: item.title || item.attack_category || "Security Event",
      subtitle:
        item.subtitle ||
        `${item.attack_label || "Unknown attack"} | ${item.risk_level || "Unknown risk"}`,
      page: item.page || "Dashboard",
    }));

    const seen = new Set();
    const mergedResults = [...backendResults, ...localResults].filter((item) => {
      const key = `${item.type}-${item.title}-${item.subtitle}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    setSearchResults(mergedResults.slice(0, 8));
  } catch (error) {
    setSearchResults(localResults);
  }
}, [searchTerm, searchIndex]);

  const dashboardTotals = useMemo(
    () => ({
      totalThreats: stats?.total_threats ?? 0,
      criticalAlerts: stats?.critical_alerts ?? 0,
      highRisk: stats?.high_risk ?? 0,
      modelAccuracy: stats?.model_accuracy || "Pending",
      featuresUsed: stats?.features_used ?? 0,
    }),
    [stats]
  );

  const latestIncident = useMemo(
    () => stats?.latest_attack || null,
    [stats]
  );

  const activeActions = useMemo(
    () =>
      latestIncident?.response_actions?.length
        ? latestIncident.response_actions.map((item) => item.action_name)
        : latestIncident?.recommended_actions || [],
    [latestIncident]
  );

  const aiResponseMetrics = useMemo(() => {
    const summary = stats?.ai_response_summary;

    return {
      totalActions: summary?.total_actions ?? aiResponses.length,
      executedActions:
        summary?.executed_actions ??
        aiResponses.filter((item) => item.status === "Executed").length,
      containmentStatus: summary?.containment_status || "No Events",
      averageConfidence: summary?.average_confidence,
    };
  }, [stats, aiResponses]);

  const threatIntelSummary = useMemo(() => {
    const summary = threatIntel?.summary || stats?.threat_intel_summary || {};

    return {
      enrichedEvents: summary.enriched_events ?? 0,
      iocMatches: summary.ioc_matches ?? 0,
      maliciousEvents: summary.malicious_events ?? 0,
      watchlistEvents: summary.watchlist_events ?? 0,
      repeatSourceEvents: summary.repeat_source_events ?? 0,
    };
  }, [threatIntel, stats]);

  const speak = useCallback(
    (message) => {
      if (!voiceEnabled || !window.speechSynthesis) return;

      const voiceMessage = new SpeechSynthesisUtterance(message);
      voiceMessage.rate = 0.9;
      voiceMessage.pitch = 1;
      voiceMessage.volume = 1;

      window.speechSynthesis.cancel();
      window.speechSynthesis.speak(voiceMessage);
    },
    [voiceEnabled]
  );

  const loadHistory = useCallback(() => {
    fetch(apiUrl("/attack_history?source=live"))
      .then((res) => res.json())
      .then((data) => {
        const rows = Array.isArray(data)
          ? data
          : data.history || data.results || data.data || [];

        setHistory(rows);
      })
      .catch(() => {
        setHistory([]);
        setConnectionError("Backend connection issue: live attack history is unavailable.");
      });
  }, []);

  const loadStats = useCallback(() => {
    fetch(apiUrl("/dashboard_stats?source=live"))
      .then((res) => res.json())
      .then((data) => {
        setStats(data);
        setConnectionError("");
      })
      .catch(() => {
        setStats(null);
        setConnectionError("Backend connection issue: dashboard statistics are unavailable.");
      });
  }, []);

  const loadAIResponses = useCallback(() => {
    fetch(apiUrl("/ai_responses?source=live&limit=24"))
      .then((res) => res.json())
      .then((data) => {
        setAiResponses(Array.isArray(data.responses) ? data.responses : []);
      })
      .catch(() => {
        setAiResponses([]);
        setConnectionError("Backend connection issue: AI response logs are unavailable.");
      });
  }, []);

  const loadThreatIntel = useCallback(() => {
    fetch(apiUrl("/threat_intel?source=live"))
      .then((res) => res.json())
      .then((data) => setThreatIntel(data))
      .catch(() => {
        setThreatIntel(null);
        setConnectionError("Backend connection issue: threat intelligence is unavailable.");
      });
  }, []);

  const loadDeviceStats = useCallback(() => {
    fetch(apiUrl("/device_stats"))
      .then((res) => res.json())
      .then((data) => setDeviceStats(data))
      .catch(() => {
        setDeviceStats(null);
        setConnectionError("Device monitoring endpoint is unavailable.");
      });
  }, []);

  const handleLiveTestTypeChange = useCallback((attackType) => {
    const profile = liveTestProfiles[attackType] || liveTestProfiles.dos;

    setLiveTestForm({
      attackType,
      country: profile.country,
      ip: profile.ip,
      sourceActivity: profile.sourceActivity,
    });
    setLiveTestStatus("");
  }, []);

  const sendLiveTestEvent = useCallback(async () => {
    setLiveTestBusy(true);
    setLiveTestStatus("Sending live event into EvoGuard...");

    const payload = {
      attack_type: liveTestForm.attackType,
      country: liveTestForm.country,
      ip: liveTestForm.ip,
      source_activity: liveTestForm.sourceActivity,
    };

    try {
      const response = await fetch(apiUrl("/ingest_event"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        throw new Error("Live event intake failed");
      }

      const data = await response.json();
      setHistory((prev) => prependUniqueById(prev, data, 50));
      setSelectedMapAttackId(`LIVE-${data.id}`);
      setLiveTestStatus(
        `${data.attack_category} accepted from ${data.country}. AI response: ${data.risk_level} risk, ${data.risk_score}/100.`
      );
      setToast(`Live event received: ${data.attack_category}`);
      window.setTimeout(() => setToast(null), 4200);

      loadStats();
      loadHistory();
      loadAIResponses();
      loadThreatIntel();
    } catch (error) {
      setLiveTestStatus("Could not send the live event. Check that the Flask backend is running.");
      setConnectionError("Backend connection issue: live event intake is unavailable.");
    } finally {
      setLiveTestBusy(false);
    }
  }, [liveTestForm, loadAIResponses, loadHistory, loadStats, loadThreatIntel]);

  const resetLiveEvents = useCallback(async () => {
    setLiveTestBusy(true);
    setLiveTestStatus("Clearing live dashboard events...");

    try {
      const response = await fetch(
        apiUrl("/reset_attack_history?source=live&confirm=RESET"),
        { method: "POST" }
      );

      if (!response.ok) {
        throw new Error("Live event reset failed");
      }

      setHistory([]);
      setAiResponses([]);
      setSelectedMapAttackId("");
      setLiveTestStatus("Live dashboard events cleared. Simulation history was not touched.");
      loadStats();
      loadThreatIntel();
    } catch (error) {
      setLiveTestStatus("Could not clear live events. Check the backend console.");
    } finally {
      setLiveTestBusy(false);
    }
  }, [loadStats, loadThreatIntel]);

  const applyAttackEvent = useCallback(
    (event) => {
      const type = attackProfiles[event.type] ? event.type : "normal";
      const riskKey = event.risk_level.toLowerCase();
      const historyItem = {
        id: event.id,
        attack_label: event.attack_label,
        attack_category: event.attack_category,
        risk_score: event.risk_score,
        risk_level: event.risk_level,
        timestamp: event.timestamp,
      };

      setAttack(event);
      setLiveMapAttacks((prev) => [event, ...prev].slice(0, 10));
      setSimulationHistory((prev) => [historyItem, ...prev].slice(0, 25));

      setSimStats((prev) => ({
        ...prev,
        total: prev.total + 1,
        critical: riskKey === "critical" ? prev.critical + 1 : prev.critical,
        high: riskKey === "high" ? prev.high + 1 : prev.high,
        medium: riskKey === "medium" ? prev.medium + 1 : prev.medium,
        low: riskKey === "low" ? prev.low + 1 : prev.low,
        [type]: prev[type] + 1,
      }));

      setWeeklyData((prev) =>
        prev.map((item) =>
          item.day === getCurrentChartDay()
            ? { ...item, attacks: item.attacks + 1 }
            : item
        )
      );

      setSocLogs((prev) =>
        [
          `[AI] ${event.attack_category} classified as ${event.attack_label}.`,
          `[RISK] Score calculated: ${event.risk_score}/100 (${event.risk_level}).`,
          `[GEO] Source identified: ${event.country} - ${event.ip}.`,
          "[MITIGATION] Autonomous response actions generated.",
          "[AI] Autonomous containment status updated.",
          ...prev,
        ].slice(0, 14)
      );

      setLiveThreats((prev) =>
        [
          `[${event.time}] ${event.risk_level} ${event.attack_category} from ${event.country} (${event.ip})`,
          ...prev,
        ].slice(0, 8)
      );

      setActivityFeed((prev) =>
        [
          `[${event.time}] ${event.attack_category} detected.`,
          `[${event.time}] Risk score assigned: ${event.risk_score}/100.`,
          `[${event.time}] AI generated autonomous response actions.`,
          `[${event.time}] Event added to local incident history.`,
          ...prev,
        ].slice(0, 12)
      );

      setToast(`${event.attack_category} detected - Risk: ${event.risk_level}`);
      setSocAlert({
        title: `${event.risk_level} Alert`,
        message: `${event.attack_category} detected from ${event.country}. Risk score: ${event.risk_score}/100`,
        level: event.risk_level,
      });

      window.setTimeout(() => setSocAlert(null), 6000);
      window.setTimeout(() => setToast(null), 4200);

      if (event.risk_level !== "Low") {
        speak(
          `${event.risk_level} risk ${event.attack_category} detected. Risk score is ${event.risk_score} out of 100. EvoGuard AI is generating response actions.`
        );
      }
    },
    [speak]
  );

  const simulateAttack = useCallback(
    (type) => {
      fetch(apiUrl(`/simulate_attack/${type}`))
        .then((res) => (res.ok ? res.json() : null))
        .catch(() => {
          setToast("Backend unavailable. Running local simulation fallback.");
          window.setTimeout(() => setToast(null), 4200);
          return null;
        })
        .then((apiData) => {
          const event = buildAttackEvent(type, apiData);
          applyAttackEvent(event);

          // Simulation events stay inside the testing lab. The main dashboard
          // continues to load only live backend events.
        });
    },
    [applyAttackEvent]
  );


  const resetSimulationSession = useCallback(() => {
    setAttack(null);
    setLiveMapAttacks([]);
    setSimulationHistory([]);
    setSimStats(initialSimStats);
    setWeeklyData(initialWeeklyData);
    setAutoSimulation(false);
    setLiveThreats([
      "[READY] No active threats. Simulation engine is standing by.",
    ]);
    setActivityFeed((prev) => [
      `[${new Date().toLocaleTimeString()}] Simulation lab session reset.`,
      ...prev,
    ].slice(0, 12));
  }, []);
  const handleLogin = async (e) => {
    e.preventDefault();

    try {
      const response = await fetch(apiUrl("/auth/login"), {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(loginForm),
      });

      const data = await response.json();

      if (!response.ok || !data.authenticated) {
        throw new Error(data.message || "Invalid username or password.");
      }

      localStorage.setItem("evoguard_logged_in", "true");
      localStorage.setItem("evoguard_user", JSON.stringify(data.user));
      setCurrentUser(data.user);
      setIsLoggedIn(true);
      setLoginError("");
      return;
    } catch (error) {
      if (loginForm.username === "mayed" && loginForm.password === "mayed123") {
        const fallbackUser = {
          username: "mayed",
          role: "AI Defense Operator",
          access_level: "Administrator",
        };

        localStorage.setItem("evoguard_logged_in", "true");
        localStorage.setItem("evoguard_user", JSON.stringify(fallbackUser));
        setCurrentUser(fallbackUser);
        setIsLoggedIn(true);
        setLoginError("");
        return;
      }

      setLoginError(error.message || "Invalid username or password.");
    }
  };

  const handleLogout = () => {
    fetch(apiUrl("/auth/logout"), {
      method: "POST",
      credentials: "include",
    }).catch(() => {});

    localStorage.removeItem("evoguard_logged_in");
    localStorage.removeItem("evoguard_user");
    window.speechSynthesis?.cancel();
    setIsLoggedIn(false);
    setCurrentUser(null);
    setLoginForm({ username: "", password: "" });
    setAttack(null);
    setChatAnswer("");
    setChatQuestion("");
    setAutoSimulation(false);
    welcomeSpoken.current = false;
  };

  useEffect(() => {
    if (!isLoggedIn) return;

    fetch(apiUrl("/auth/session"), {
      credentials: "include",
    })
      .then((res) => res.json())
      .then((data) => {
        if (data.authenticated && data.user) {
          localStorage.setItem("evoguard_user", JSON.stringify(data.user));
          setCurrentUser(data.user);
        }
      })
      .catch(() => {});
  }, [isLoggedIn]);

  const askAssistant = () => {
    if (!chatQuestion.trim()) return;

    fetch(apiUrl(`/ai_assistant/${encodeURIComponent(chatQuestion)}`))
      .then((res) => res.json())
      .then((data) => setChatAnswer(data.answer))
      .catch(() => {
        const latest = attack
          ? `${attack.attack_category} from ${attack.country} has ${attack.risk_level} risk with score ${attack.risk_score}/100. Recommended action: ${attack.recommended_actions[0]}`
          : "No active simulated incident is available yet. Run a simulation to generate AI analysis.";
        setChatAnswer(latest);
      });
  };

  useEffect(() => {
    if (!isLoggedIn) return;

    loadStats();
    loadHistory();
    loadAIResponses();
    loadThreatIntel();
    loadDeviceStats();

    if (!welcomeSpoken.current) {
      speak(
        "Welcome back, Mayed. EvoGuard AI defense platform is online. Threat monitoring is active."
      );
      welcomeSpoken.current = true;
    }

    const interval = setInterval(() => {
      loadStats();
      loadHistory();
      loadAIResponses();
      loadThreatIntel();
      loadDeviceStats();
    }, 5000);

    return () => clearInterval(interval);
  }, [
    isLoggedIn,
    loadStats,
    loadHistory,
    loadAIResponses,
    loadThreatIntel,
    loadDeviceStats,
    speak,
  ]);

  useEffect(() => {
    if (!isLoggedIn) return undefined;

    const socket = io(API_BASE_URL, {
      transports: ["websocket", "polling"],
      reconnection: true,
      reconnectionAttempts: 10,
      reconnectionDelay: 1200,
    });

    socketRef.current = socket;
    setRealtimeStatus("Connecting...");

    socket.on("connect", () => {
      setRealtimeStatus("Realtime Connected");
      setConnectionError("");
      socket.emit("evoguard:request_sync", { source: "live" });
    });

    socket.on("disconnect", () => {
      setRealtimeStatus("Polling Fallback");
    });

    socket.on("connect_error", () => {
      setRealtimeStatus("Polling Fallback");
    });

    socket.on("evoguard:connected", (payload) => {
      if (payload?.source !== "live") return;
      if (payload.stats) setStats(payload.stats);
      if (Array.isArray(payload.history)) setHistory(payload.history);
      if (Array.isArray(payload.responses)) setAiResponses(payload.responses);
      loadThreatIntel();
    });

    socket.on("evoguard:new_attack", (payload) => {
      if (payload?.source !== "live" || !payload.attack) return;

      const event = payload.attack;
      const now = new Date().toLocaleTimeString();

      setHistory((prev) => prependUniqueById(prev, event, 50));
      if (payload.stats) setStats(payload.stats);
      setSelectedMapAttackId(`LIVE-${event.id}`);
      setToast(`Realtime event received: ${event.attack_category}`);
      setLiveThreats((prev) =>
        [
          `[${now}] ${event.risk_level} ${event.attack_category} from ${event.country} (${event.ip})`,
          ...prev,
        ].slice(0, 8)
      );
      setActivityFeed((prev) =>
        [`[${now}] Realtime backend event received through Socket.IO.`, ...prev].slice(
          0,
          12
        )
      );
      loadThreatIntel();
      window.setTimeout(() => setToast(null), 4200);
    });

    socket.on("evoguard:ai_response", (payload) => {
      if (payload?.source !== "live") return;
      const responses = Array.isArray(payload.responses) ? payload.responses : [];
      setAiResponses((prev) => mergeUniqueById(prev, responses, 24));
    });

    socket.on("evoguard:stats_updated", (payload) => {
      if (payload?.source === "live") setStats(payload);
    });

    return () => {
      socket.disconnect();
      socketRef.current = null;
    };
  }, [isLoggedIn, loadThreatIntel]);

  useEffect(() => {
    if (!isLoggedIn) return;

    const ambientMessages = [
      "Threat intelligence database updated.",
      "Deep packet inspection engine active.",
      "Endpoint telemetry stream healthy.",
      "AI correlation engine waiting for new events.",
      "AI containment queue synchronized.",
    ];

    const interval = setInterval(() => {
      const now = new Date().toLocaleTimeString();
      setSocLogs((prev) =>
        [`[MONITOR] ${randomItem(ambientMessages)}`, ...prev].slice(0, 14)
      );
      setActivityFeed((prev) =>
        [`[${now}] Passive monitoring heartbeat received.`, ...prev].slice(
          0,
          12
        )
      );
    }, 12000);

    return () => clearInterval(interval);
  }, [isLoggedIn]);

  useEffect(() => {
    if (!liveDashboardAttacks.length) {
      setSelectedMapAttackId("");
      return;
    }

    const selectedStillExists = liveDashboardAttacks.some(
      (event) => event.id === selectedMapAttackId
    );

    if (!selectedStillExists) {
      setSelectedMapAttackId(liveDashboardAttacks[0].id);
    }
  }, [liveDashboardAttacks, selectedMapAttackId]);

  useEffect(() => {
    if (!isLoggedIn || !autoSimulation) return;

    const attackTypes = ["dos", "probe", "r2l", "u2r", "normal"];
    const interval = setInterval(() => {
      simulateAttack(randomItem(attackTypes));
    }, 7000);

    return () => clearInterval(interval);
  }, [isLoggedIn, autoSimulation, simulateAttack]);

  if (!isLoggedIn) {
    return (
      <div className="login-page">
        <div className="login-card">
          <img src={logoIcon} alt="EvoGuard" className="login-logo-img" />
          <h1>EvoGuard</h1>
          <p>Agentic AI Cyber Defense Login</p>

          <form onSubmit={handleLogin}>
            <input
              type="text"
              placeholder="Username"
              value={loginForm.username}
              onChange={(e) =>
                setLoginForm({ ...loginForm, username: e.target.value })
              }
            />

            <input
              type="password"
              placeholder="Password"
              value={loginForm.password}
              onChange={(e) =>
                setLoginForm({ ...loginForm, password: e.target.value })
              }
            />

            {loginError && <div className="login-error">{loginError}</div>}

            <button type="submit">Login</button>
          </form>

          <span className="login-hint">Authorized AI defense access only</span>
        </div>
      </div>
    );
  }

  return (
    <>
      {toast && <div className="toast-alert">{toast}</div>}
      {connectionError && (
        <div className="connection-banner">{connectionError}</div>
      )}

      <div className="app">
        <aside className="sidebar">
          <div className="brand">
            <img src={logoIcon} alt="EvoGuard" className="brand-logo" />
            <div>
              <h2>EvoGuard</h2>
              <p>Agentic AI Defense</p>
            </div>
          </div>

          <nav>
            {navItems.map(({ page, icon }) => (
              <span
                key={page}
                className={activePage === page ? "active" : ""}
                onClick={() => setActivePage(page)}
              >
                <span className="nav-icon">{icon}</span>
                {page}
              </span>
            ))}
          </nav>

          <div className="system-box">
            <p>Logged in as</p>
            <h3>{currentUser?.username || "mayed"}</h3>
            <button className="logout-btn" onClick={handleLogout}>
              Logout
            </button>
          </div>
        </aside>

        <main className="content">
          {socAlert && (
            <div className={`soc-alert ${socAlert.level.toLowerCase()}`}>
              <h3>{socAlert.title}</h3>
              <p>{socAlert.message}</p>
            </div>
          )}

          <header className="header">
            <div>
              <h1>{activePage}</h1>
              <p>Real-time agentic cyber defense monitoring</p>
            </div>

            <div className="top-search">
              <input
                type="search"
                placeholder="Search attacks, pages, countries..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleSearch();
                }}
              />
              <button onClick={handleSearch} aria-label="Search">
                Go
              </button>
            </div>

            <div
              className={`header-right ${
                realtimeStatus === "Realtime Connected"
                  ? "socket-live"
                  : "socket-fallback"
              }`}
            >
              <span className="dot"></span>
              <span>{realtimeStatus}</span>
            </div>
          </header>

          {searchResults.length > 0 && (
            <section className="search-results-panel">
              {searchResults.map((result, index) => (
                <button
                  key={`${result.type}-${result.title}-${index}`}
                  className="search-result-item"
                  onClick={() => {
                    setActivePage(result.page);
                    setSearchResults([]);
                    setSearchTerm("");
                  }}
                >
                  <strong>{result.type}</strong>
                  <span>{result.title}</span>
                  <small>{result.subtitle}</small>
                </button>
              ))}
            </section>
          )}

          {activePage === "Dashboard" && (
            <>
              <section className="stats-grid">
                <div className="stat-card">
                  <span>Total Threats</span>
                  <h2>{dashboardTotals.totalThreats}</h2>
                  <p>Backend incident records</p>
                </div>
                <div className="stat-card red">
                  <span>Critical Alerts</span>
                  <h2>{dashboardTotals.criticalAlerts}</h2>
                  <p>AI containment priority</p>
                </div>
                <div className="stat-card orange">
                  <span>High Risk</span>
                  <h2>{dashboardTotals.highRisk}</h2>
                  <p>Autonomous response queue</p>
                </div>
                <div className="stat-card green">
                  <span>AI Defense Score</span>
                  <h2>{dashboardTotals.modelAccuracy}</h2>
                  <p>Based on received attacks and AI response</p>
                </div>
              </section>

              {deviceStats && (
                <section className="device-grid">
                  <div className="stat-card">
                    <span>Device Status</span>
                    <h2>{deviceStats.status}</h2>
                    <p>Real monitored system</p>
                  </div>
                  <div className="stat-card">
                    <span>CPU Usage</span>
                    <h2>{deviceStats.cpu_usage}%</h2>
                    <p>Live processor load</p>
                  </div>
                  <div className="stat-card">
                    <span>Bytes Sent</span>
                    <h2>{formatBytes(deviceStats.bytes_sent)}</h2>
                    <p>Outbound network traffic</p>
                  </div>
                  <div className="stat-card">
                    <span>Bytes Received</span>
                    <h2>{formatBytes(deviceStats.bytes_received)}</h2>
                    <p>Inbound network traffic</p>
                  </div>
                  <div className="stat-card">
                    <span>Memory Usage</span>
                    <h2>{deviceStats.memory_usage}%</h2>
                    <p>RAM utilization</p>
                  </div>
                  <div className="stat-card">
                    <span>Disk Usage</span>
                    <h2>{deviceStats.disk_usage}%</h2>
                    <p>Storage usage</p>
                  </div>
                </section>
              )}

              <section className="main-grid">
                <div className="panel chart-panel">
                  <div className="panel-title">
                    <h3>Weekly Attack Trend</h3>
                    <span>Backend event activity</span>
                  </div>
                  <ResponsiveContainer width="100%" height={280}>
                    <BarChart data={dashboardWeeklyData}>
                      <XAxis dataKey="day" stroke="#94a3b8" />
                      <YAxis stroke="#94a3b8" allowDecimals={false} />
                      <Tooltip
                        cursor={{ fill: "rgba(0, 255, 224, 0.06)" }}
                        contentStyle={{
                          background: "#080014",
                          border: "1px solid rgba(0, 255, 224, 0.18)",
                          borderRadius: "8px",
                          color: "#f7ecff",
                        }}
                      />
                      <Bar dataKey="attacks" fill="#ef4444" radius={[6, 6, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                <div className="panel">
                  <div className="panel-title">
                    <h3>Attack Distribution</h3>
                    <span>Categories</span>
                  </div>
                  {dashboardAttackData.some((item) => item.value > 0) ? (
                      <ResponsiveContainer width="100%" height={280}>
                        <PieChart>
                          <Pie
                            data={dashboardAttackData}
                            dataKey="value"
                            nameKey="name"
                            outerRadius={86}
                            label
                          >
                            {dashboardAttackData.map((entry, index) => (
                              <Cell key={entry.name} fill={COLORS[index % COLORS.length]} />
                            ))}
                          </Pie>
                          <Tooltip
                            contentStyle={{
                              background: "#080014",
                              border: "1px solid rgba(0, 255, 224, 0.18)",
                              borderRadius: "8px",
                              color: "#f7ecff",
                            }}
                          />
                        </PieChart>
                      </ResponsiveContainer>
                    ) : (
                      <div className="empty-box chart-empty">
                        No attack distribution yet. Run a test from the Simulation Center.
                      </div>
                    )}
                </div>
              </section>

              <section className="bottom-grid">
                <div className="panel">
                  <div className="panel-title">
                    <h3>Live AI Defense Terminal</h3>
                    <span>Backend event console</span>
                  </div>
                  <div className="soc-terminal">
                    {socLogs.map((log, index) => (
                      <div key={index} className="soc-terminal-line">
                        {log}
                      </div>
                    ))}
                  </div>
                </div>

                <div className="panel">
                  <div className="panel-title">
                    <h3>Global Threat Map</h3>
                    <span>Live attack origin tracking</span>
                  </div>
                  <ThreatMap
                    liveAttacks={liveDashboardAttacks}
                    emptyTitle="No live attack routes"
                    emptyMessage="Send a live event to /ingest_event to draw routes."
                  />
                </div>

                <div className="panel">
                  <div className="panel-title">
                    <h3>Agentic AI Analysis</h3>
                    <span>Decision engine</span>
                  </div>
                  {latestIncident ? (
                    <div className="analysis-box">
                      <h4>{latestIncident.attack_category}</h4>
                      <p><b>Attack:</b> {latestIncident.attack_label}</p>
                      <p>
                        <b>Source:</b>{" "}
                        {latestIncident.country || "Database"}
                        {latestIncident.ip ? ` - ${latestIncident.ip}` : ""}
                      </p>
                      <p><b>Risk:</b> {latestIncident.risk_score}/100</p>
                      <p>
                        <b>Risk Level:</b>{" "}
                        <span className={`risk-badge ${(latestIncident.risk_level || "low").toLowerCase()}`}>
                          {latestIncident.risk_level}
                        </span>
                      </p>
                      <p><b>Explanation:</b> {latestIncident.explanation}</p>
                    </div>
                  ) : (
                    <div className="empty-box">
                      No incident records available yet. Run a simulation to generate database events.
                    </div>
                  )}
                </div>
              </section>

              <section className="bottom-grid">
                <div className="panel">
                  <div className="panel-title">
                    <h3>AI Response Execution Center</h3>
                    <span>Autonomous containment</span>
                  </div>

                  <div className="response-metrics-row">
                    <div>
                      <strong>{aiResponseMetrics.executedActions}</strong>
                      <span>Executed</span>
                    </div>
                    <div>
                      <strong>{aiResponseMetrics.containmentStatus}</strong>
                      <span>Status</span>
                    </div>
                    <div>
                      <strong>
                        {aiResponseMetrics.averageConfidence
                          ? `${Math.round(aiResponseMetrics.averageConfidence)}%`
                          : "N/A"}
                      </strong>
                      <span>Confidence</span>
                    </div>
                  </div>

                  {aiResponses.length ? (
                    <div className="ai-response-timeline">
                      {aiResponses.slice(0, 5).map((item) => (
                        <div key={item.id} className="ai-response-step">
                          <div className="ai-response-marker"></div>
                          <div>
                            <strong>{item.action_name}</strong>
                            <p>{item.explanation}</p>
                            <span>
                              {item.execution_stage} | {item.status} |{" "}
                              {Math.round(item.confidence || 0)}%
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : activeActions.length ? (
                    <div className="ai-actions-list">
                      {activeActions.map((action, index) => (
                        <div key={index} className="ai-action-item">
                          <span className="ai-action-dot"></span>
                          <span>{action}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="empty-box">
                      No autonomous response has been generated yet.
                    </div>
                  )}
                </div>

                <div className="panel">
                  <div className="panel-title">
                    <h3>Live AI Threat Stream</h3>
                    <span>Continuous AI monitoring</span>
                  </div>
                  <div className="live-threat-feed">
                    {liveThreats.map((threat, index) => (
                      <div key={index} className="live-threat-item">
                        <span className="live-dot"></span>
                        {threat}
                      </div>
                    ))}
                  </div>
                </div>

                <div className="panel">
                  <div className="panel-title">
                    <h3>Live AI Activity Feed</h3>
                    <span>Real-time AI monitoring</span>
                  </div>
                  <div className="activity-feed">
                    {activityFeed.map((log, index) => (
                      <div className="activity-line" key={index}>
                        {log}
                      </div>
                    ))}
                  </div>
                </div>
              </section>

              <section className="history-grid">
                <div className="panel history-panel">
                  <div className="panel-title">
                    <h3>Recent Attack History</h3>
                    <span>Database events</span>
                  </div>
                  <table className="history-table">
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>Attack</th>
                        <th>Category</th>
                        <th>Risk</th>
                        <th>Level</th>
                        <th>Timestamp</th>
                      </tr>
                    </thead>
                    <tbody>
                      {history.slice(0, 8).map((item) => (
                        <tr key={item.id}>
                          <td>{item.id}</td>
                          <td>{item.attack_label}</td>
                          <td>{item.attack_category}</td>
                          <td>{item.risk_score}/100</td>
                          <td>{item.risk_level}</td>
                          <td>{item.timestamp}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            </>
          )}

          {activePage === "Threat Intel" && (
            <section className="threat-intel-page">
              <div className="intel-grid">
                <div className="panel">
                  <div className="panel-title">
                    <h3>Threat Intel Overview</h3>
                    <span>IOC enrichment</span>
                  </div>
                  <div className="severity-list">
                    <div className="severity-item critical">
                      <strong>Malicious</strong>
                      <span>{threatIntelSummary.maliciousEvents} enriched events</span>
                    </div>
                    <div className="severity-item high">
                      <strong>Watchlist</strong>
                      <span>{threatIntelSummary.watchlistEvents} monitored events</span>
                    </div>
                    <div className="severity-item medium">
                      <strong>IOC Matches</strong>
                      <span>{threatIntelSummary.iocMatches} matched indicators</span>
                    </div>
                    <div className="severity-item low">
                      <strong>Enriched</strong>
                      <span>{threatIntelSummary.enrichedEvents} live events</span>
                    </div>
                  </div>
                </div>

                <div className="panel">
                  <div className="panel-title">
                    <h3>Top Enriched Sources</h3>
                    <span>IOC correlation</span>
                  </div>
                  <div className="country-list">
                    {(threatIntel?.top_sources || []).length ? (
                      threatIntel.top_sources.slice(0, 5).map((source) => (
                        <div key={source.indicator}>
                          <strong>{source.country}</strong>
                          <span>
                            {source.indicator} | {source.reputation} | {source.events} events
                          </span>
                        </div>
                      ))
                    ) : (
                      <div>
                        <strong>No live sources yet</strong>
                        <span>Send a live event to enrich threat intel</span>
                      </div>
                    )}
                  </div>
                </div>

                <div className="panel">
                  <div className="panel-title">
                    <h3>MITRE Technique Coverage</h3>
                    <span>ATT&CK mapping</span>
                  </div>
                  <div className="mitre-list">
                    {(threatIntel?.mitre_techniques || []).slice(0, 5).map((item) => (
                      <div key={item.technique} className="mitre-item">
                        <strong>{item.technique}</strong>
                        <span>{item.tactic}</span>
                        <small>{item.events} events</small>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div className="intel-grid-two">
                <div className="panel">
                  <div className="panel-title">
                    <h3>IOC Watchlist</h3>
                    <span>Local threat database</span>
                  </div>
                  <div className="ioc-list">
                    {(threatIntel?.iocs || []).slice(0, 8).map((ioc) => (
                      <div className="ioc-item" key={`${ioc.indicator_type}-${ioc.indicator_value}`}>
                        <div>
                          <strong>{ioc.indicator_value}</strong>
                          <p>{ioc.indicator_type} | {ioc.notes}</p>
                        </div>
                        <span
                          className={`intel-chip ${String(ioc.reputation)
                            .toLowerCase()
                            .replace(/\s+/g, "-")}`}
                        >
                          {ioc.reputation} {Math.round(ioc.confidence || 0)}%
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="panel">
                  <div className="panel-title">
                    <h3>AI Intel Recommendation</h3>
                    <span>Enriched decision context</span>
                  </div>
                  <div className="intel-recommendation">
                    {latestIncident?.threat_intel ? (
                      <>
                        <p>
                          Latest live event reputation is{" "}
                          <b>{latestIncident.threat_intel.reputation}</b>.{" "}
                          {latestIncident.threat_intel.summary}
                        </p>
                        <p>
                          <b>MITRE:</b> {latestIncident.threat_intel.mitre_technique}
                        </p>
                      </>
                    ) : (
                      <p>
                        EvoGuard enriches live events with IOC reputation, source
                        history, and MITRE ATT&CK mapping before choosing AI actions.
                      </p>
                    )}
                    <ul>
                      {(threatIntel?.recommendations || [
                        "Send a live event to generate IOC-based AI recommendations.",
                      ]).map((action, index) => (
                        <li key={index}>{action}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>

              <div className="panel">
                <div className="panel-title">
                  <h3>Enriched Event Timeline</h3>
                  <span>Latest live intelligence</span>
                </div>
                <div className="timeline">
                  {(threatIntel?.recent_enriched || []).length ? (
                    threatIntel.recent_enriched.slice(0, 6).map((item) => (
                      <div key={item.id}>
                        <strong>
                          {item.timestamp} | {item.threat_intel?.reputation || "No IOC Match"}
                        </strong>
                        <p>
                          {item.attack_category} mapped to{" "}
                          {item.threat_intel?.mitre_technique || item.mitre_technique}.
                        </p>
                      </div>
                    ))
                  ) : (
                    <p>
                      No enriched live events yet. Send a live event from the Attack
                      Map to populate IOC and MITRE context.
                    </p>
                  )}
                </div>
              </div>
            </section>
          )}

          {activePage === "Attack Map" && (
            <section className="map-page">
              <div className="map-page-header">
                <div>
                  <h2>Global Cyber Attack Map</h2>
                  <p>Live attack origin tracking toward protected UAE infrastructure</p>
                </div>

                <div className="map-status">
                  <span className="dot"></span>
                  Live Threat Tracking
                </div>
              </div>

              <section className="live-intake-panel panel">
                <div className="live-intake-copy">
                  <span>Live Threat Intake</span>
                  <h3>Send Real-Style Events Into The Live Dashboard</h3>
                  <p>
                    These events enter the backend through /ingest_event and update the
                    real Dashboard, Attack Map, reports, AI analysis, and history.
                  </p>
                </div>

                <div className="live-intake-form">
                  <label>
                    Attack Type
                    <select
                      value={liveTestForm.attackType}
                      onChange={(event) => handleLiveTestTypeChange(event.target.value)}
                    >
                      {Object.entries(liveTestProfiles).map(([type, profile]) => (
                        <option key={type} value={type}>
                          {profile.label}
                        </option>
                      ))}
                    </select>
                  </label>

                  <label>
                    Source Country
                    <input
                      type="text"
                      value={liveTestForm.country}
                      onChange={(event) =>
                        setLiveTestForm((prev) => ({
                          ...prev,
                          country: event.target.value,
                        }))
                      }
                    />
                  </label>

                  <label>
                    Source IP
                    <input
                      type="text"
                      value={liveTestForm.ip}
                      onChange={(event) =>
                        setLiveTestForm((prev) => ({
                          ...prev,
                          ip: event.target.value,
                        }))
                      }
                    />
                  </label>

                  <label className="live-intake-wide">
                    Event Activity
                    <textarea
                      value={liveTestForm.sourceActivity}
                      onChange={(event) =>
                        setLiveTestForm((prev) => ({
                          ...prev,
                          sourceActivity: event.target.value,
                        }))
                      }
                    />
                  </label>
                </div>

                <div className="live-intake-actions">
                  <button onClick={sendLiveTestEvent} disabled={liveTestBusy}>
                    {liveTestBusy ? "Processing..." : "Send Live Event"}
                  </button>
                  <button
                    className="secondary-action"
                    onClick={resetLiveEvents}
                    disabled={liveTestBusy}
                  >
                    Clear Live Events
                  </button>
                </div>

                {liveTestStatus && (
                  <div className="live-test-status">{liveTestStatus}</div>
                )}
              </section>

              <section className="map-metrics-grid">
                <div className="stat-card">
                  <span>Live Routes</span>
                  <h2>{mapMetrics.totalRoutes}</h2>
                  <p>Backend events on map</p>
                </div>
                <div className="stat-card">
                  <span>Active Sources</span>
                  <h2>{mapMetrics.activeSources}</h2>
                  <p>Countries currently observed</p>
                </div>
                <div className="stat-card orange">
                  <span>High Impact</span>
                  <h2>{mapMetrics.highImpact}</h2>
                  <p>High and critical live routes</p>
                </div>
                <div className="stat-card green">
                  <span>Highest Risk</span>
                  <h2>{mapMetrics.highestRisk}</h2>
                  <p>Maximum live risk score</p>
                </div>
              </section>

              <div className="map-page-grid">
                <div className="map-full-panel">
                  <ThreatMap
                    height="680px"
                    liveAttacks={liveDashboardAttacks}
                    emptyTitle="No live attack routes"
                    emptyMessage="Send a live event to /ingest_event to draw routes."
                    selectedAttackId={selectedMapIncident?.id}
                    onSelectAttack={setSelectedMapAttackId}
                  />
                </div>

                <div className="map-side-panel">
                  <div className="map-panel-block">
                    <h3>Active Attack Sources</h3>

                    {liveMapSourceSummary.length > 0 ? (
                      <div className="map-source-list">
                        {liveMapSourceSummary.map((source) => (
                          <button
                            className={
                              selectedMapIncident?.country === source.country
                                ? "source-item selected"
                                : "source-item"
                            }
                            key={source.country}
                            onClick={() => setSelectedMapAttackId(source.latest.id)}
                          >
                            <strong>{source.country}</strong>
                            <span>{source.categories}</span>
                            <span>
                              {source.count} live events | peak risk {source.maxRiskScore}/100
                            </span>
                          </button>
                        ))}
                      </div>
                    ) : (
                      <div className="empty-box">
                        No live attack sources yet. Send a live event into the backend.
                      </div>
                    )}
                  </div>

                  <div className="map-panel-block">
                    <h3>Selected Route Intelligence</h3>
                    {selectedMapIncident ? (
                      <div className="map-incident-card">
                        <div className="map-incident-topline">
                          <strong>{selectedMapIncident.attack_category}</strong>
                          <span
                            className={`risk-badge ${(
                              selectedMapIncident.risk_level || "low"
                            ).toLowerCase()}`}
                          >
                            {selectedMapIncident.risk_level}
                          </span>
                        </div>
                        <p>
                          <b>Source:</b> {selectedMapIncident.country} |{" "}
                          {selectedMapIncident.ip}
                        </p>
                        <p>
                          <b>Activity:</b> {selectedMapIncident.source_activity}
                        </p>
                        <p>
                          <b>Risk Score:</b> {selectedMapIncident.risk_score}/100
                        </p>
                        <p>
                          <b>AI Mode:</b> {selectedMapIncident.response_mode}
                        </p>
                        <p>
                          <b>Containment:</b>{" "}
                          {selectedMapIncident.ai_response?.status || "Pending"}
                        </p>
                        <p>
                          <b>Confidence:</b>{" "}
                          {Math.round(selectedMapIncident.response_confidence || 0)}%
                        </p>
                      </div>
                    ) : (
                      <div className="empty-box">
                        Select a live route to view AI response intelligence.
                      </div>
                    )}
                  </div>
                </div>
              </div>

              <section className="map-detail-grid">
                <div className="panel">
                  <div className="panel-title">
                    <h3>AI Route Analysis</h3>
                    <span>Live incident context</span>
                  </div>
                  {selectedMapIncident ? (
                    <div className="analysis-box">
                      <h4>{selectedMapIncident.attack_label}</h4>
                      <p>{selectedMapIncident.explanation}</p>
                    </div>
                  ) : (
                    <div className="empty-box">No live route selected.</div>
                  )}
                </div>

                <div className="panel">
                  <div className="panel-title">
                    <h3>Autonomous Map Response</h3>
                    <span>Executed AI actions</span>
                  </div>
                  {selectedMapIncident?.response_actions?.length ? (
                    <div className="ai-response-timeline compact">
                      {selectedMapIncident.response_actions.map((action) => (
                        <div key={action.id} className="ai-response-step">
                          <div className="ai-response-marker"></div>
                          <div>
                            <strong>{action.action_name}</strong>
                            <p>{action.explanation}</p>
                            <span>
                              {action.execution_stage} | {action.status} |{" "}
                              {Math.round(action.confidence || 0)}%
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : selectedMapIncident?.recommended_actions?.length ? (
                    <div className="ai-actions-list">
                      {selectedMapIncident.recommended_actions.map((action, index) => (
                        <div key={index} className="ai-action-item">
                          <span className="ai-action-dot"></span>
                          <span>{action}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="empty-box">
                      No autonomous response available for this route yet.
                    </div>
                  )}
                </div>
              </section>
            </section>
          )}
          {activePage === "Simulation" && (
  <section className="simulation-page">
    <div className="simulation-header">
      <div>
        <h2>Attack Simulation Center</h2>
        <p>
          Run controlled cyberattack scenarios and observe EvoGuard AI response.
        </p>
      </div>

      <div className="simulation-status">
        <span className="dot"></span>
        Simulation Engine Online
      </div>
    </div>

    <section className="attack-buttons simulation-controls">
      {Object.keys(attackProfiles).map((type) => (
        <button key={type} onClick={() => simulateAttack(type)}>
          Simulate {attackProfiles[type].chartName}
        </button>
      ))}

      <button
        className={autoSimulation ? "auto-on" : ""}
        onClick={() => setAutoSimulation((prev) => !prev)}
      >
        {autoSimulation ? "Stop Auto Simulation" : "Start Auto Simulation"}
      </button>

      <button onClick={resetSimulationSession}>
        Reset Test Session
      </button>
    </section>

    <section className="simulation-summary-grid">
      <div className="stat-card">
        <span>Test Events</span>
        <h2>{simStats.total}</h2>
        <p>Current simulation session</p>
      </div>
      <div className="stat-card red">
        <span>Critical Tests</span>
        <h2>{simStats.critical}</h2>
        <p>Critical lab scenarios</p>
      </div>
      <div className="stat-card orange">
        <span>High Tests</span>
        <h2>{simStats.high}</h2>
        <p>High-risk lab scenarios</p>
      </div>
      <div className="stat-card green">
        <span>Auto Mode</span>
        <h2>{autoSimulation ? "On" : "Off"}</h2>
        <p>Simulation automation</p>
      </div>
    </section>


    <div className="simulation-result-grid">
      <div className="panel">
        <div className="panel-title">
          <h3>Latest AI Detection Result</h3>
          <span>Model output</span>
        </div>

        {attack ? (
          <div className="analysis-box">
            <h4>{attack.attack_category}</h4>
            <p><b>Attack:</b> {attack.attack_label}</p>
            <p><b>Risk Score:</b> {attack.risk_score}/100</p>
            <p><b>Risk Level:</b> {attack.risk_level}</p>
            <p><b>Explanation:</b> {attack.explanation}</p>
          </div>
        ) : (
          <div className="empty-box">
            No simulation has been executed yet.
          </div>
        )}
      </div>

      <div className="panel">
        <div className="panel-title">
          <h3>AI Autonomous Actions</h3>
          <span>Response simulation</span>
        </div>

        {attack ? (
          <ul className="actions">
            {attack.recommended_actions.map((action, index) => (
              <li key={index}>{action}</li>
            ))}
          </ul>
        ) : (
          <div className="empty-box">
            EvoGuard AI will generate autonomous response actions after a simulation.
          </div>
        )}
      </div>

      <div className="panel">
        <div className="panel-title">
          <h3>Execution Feed</h3>
          <span>Live simulation log</span>
        </div>

        <div className="simulation-log">
          <p>[READY] Simulation engine initialized.</p>
          <p>[AI] Model loaded successfully.</p>
          <p>[DB] Attack logging enabled.</p>
          {autoSimulation && <p>[AUTO] Auto simulation mode is running.</p>}
          {attack && <p>[DETECTED] {attack.attack_category} classified.</p>}
          {attack && <p>[RISK] {attack.risk_level} risk assigned.</p>}
          {attack && <p>[ACTION] Autonomous response simulation generated.</p>}
        </div>
      </div>

      <div className="panel">
        <div className="panel-title">
          <h3>Simulation Route Map</h3>
          <span>Testing lab routes</span>
        </div>
        <ThreatMap
          height="250px"
          liveAttacks={liveMapAttacks}
          emptyTitle="No simulation routes"
          emptyMessage="Run a simulation to draw test routes."
        />
      </div>
    </div>
    <section className="attack-reference-section">
      <div className="panel">
        <div className="panel-title">
          <h3>Attack Scenario Reference</h3>
          <span>Simulation meanings</span>
        </div>

        <div className="attack-reference-grid">
          {Object.entries(attackProfiles).map(([type, profile]) => (
            <div className="attack-reference-item" key={type}>
              <div>
                <strong>{profile.category}</strong>
                <p>{profile.explanation}</p>
              </div>
              <span className={`level-badge ${profile.riskLevel.toLowerCase()}`}>
                {profile.riskLevel}
              </span>
            </div>
          ))}
        </div>
      </div>
    </section>
    <section className="history-grid">
      <div className="panel history-panel">
        <div className="panel-title">
          <h3>Recent Simulation Events</h3>
          <span>Testing lab only</span>
        </div>
        {simulationHistory.length ? (
          <table className="history-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Attack</th>
                <th>Category</th>
                <th>Risk</th>
                <th>Level</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {simulationHistory.slice(0, 8).map((item) => (
                <tr key={item.id}>
                  <td>{item.id}</td>
                  <td>{item.attack_label}</td>
                  <td>{item.attack_category}</td>
                  <td>{item.risk_score}/100</td>
                  <td>{item.risk_level}</td>
                  <td>{item.timestamp}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="empty-box">
            No simulation events in this session yet.
          </div>
        )}
      </div>
    </section>  </section>
)}

          {activePage === "Reports" && (
            <section className="reports-page">
              <div className="reports-header">
                <div>
                  <h2>Reports Center</h2>
                  <p>Generate, download, and email EvoGuard security reports.</p>
                </div>
                <div className="reports-status">
                  <span className="dot"></span>
                  Reporting Engine Online
                </div>
              </div>

              <div className="panel">
                <div className="panel-title">
                  <h3>Latest Generated Incident</h3>
                  <span>AI report preview</span>
                </div>
                {attack ? (
                  <div className="report-analyst-box">
                    <p><b>Incident:</b> {attack.id}</p>
                    <p><b>Attack Type:</b> {attack.attack_category}</p>
                    <p><b>Attack Label:</b> {attack.attack_label}</p>
                    <p><b>Source:</b> {attack.country} - {attack.ip}</p>
                    <p><b>Risk Score:</b> {attack.risk_score}/100</p>
                    <p><b>Risk Level:</b> {attack.risk_level}</p>
                    <p><b>AI Explanation:</b> {attack.explanation}</p>
                  </div>
                ) : (
                  <div className="empty-box">
                    Run an attack simulation to generate an incident preview.
                  </div>
                )}
              </div>

              <div className="reports-grid">
                <div className="report-card">
                  <h3>Incident Report</h3>
                  <p>Download the latest AI-classified incident report as PDF.</p>
                  <button onClick={() => window.open(apiUrl("/download_report"))}>
                    Download PDF
                  </button>
                </div>
                <div className="report-card">
                  <h3>Weekly Report</h3>
                  <p>Email weekly AI defense summary to the configured operator email.</p>
                  <button onClick={() => window.open(apiUrl("/send_weekly_report"))}>
                    Send Weekly
                  </button>
                </div>
                <div className="report-card">
                  <h3>Monthly Report</h3>
                  <p>Email end-of-month threat analysis and attack summary.</p>
                  <button onClick={() => window.open(apiUrl("/send_monthly_report"))}>
                    Send Monthly
                  </button>
                </div>
                <div className="report-card">
                  <h3>Yearly Report</h3>
                  <p>Email annual EvoGuard security performance summary.</p>
                  <button onClick={() => window.open(apiUrl("/send_yearly_report"))}>
                    Send Yearly
                  </button>
                </div>
              </div>

              <div className="reports-summary-grid">
                <div className="panel">
                  <div className="panel-title">
                    <h3>Report Summary</h3>
                    <span>Backend metrics</span>
                  </div>
                  <div className="report-summary-list">
                    <div><strong>Total Logged Threats</strong><span>{dashboardTotals.totalThreats}</span></div>
                    <div><strong>High Risk Events</strong><span>{dashboardTotals.highRisk}</span></div>
                    <div><strong>Critical Alerts</strong><span>{dashboardTotals.criticalAlerts}</span></div>
                    <div><strong>AI Defense Score</strong><span>{dashboardTotals.modelAccuracy}</span></div>
                  </div>
                </div>

                <div className="panel">
                  <div className="panel-title">
                    <h3>AI Response Summary</h3>
                    <span>AI generated</span>
                  </div>
                  <div className="report-analyst-box">
                    <p>
                      EvoGuard has processed simulated network events and
                      classified attacks based on risk level, category, source,
                      and autonomous response priority.
                    </p>
                    <ul>
                      {(attack?.recommended_actions || [
                        "Run attack simulations to populate this AI response summary.",
                      ]).map((action, index) => (
                        <li key={index}>{action}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            </section>
          )}

          {activePage === "Settings" && (
            <section className="settings-page">
              <div className="settings-header">
                <div>
                  <h2>System Settings</h2>
                  <p>Manage operator access, AI status, and platform configuration.</p>
                </div>
                <div className="settings-status">
                  <span className="dot"></span>
                  System Online
                </div>
              </div>

              <div className="settings-grid">
                <div className="panel">
                  <div className="panel-title">
                    <h3>Operator Profile</h3>
                    <span>Current user</span>
                  </div>
                  <div className="settings-list">
                    <div><strong>Username</strong><span>{currentUser?.username || "mayed"}</span></div>
                    <div><strong>Role</strong><span>{currentUser?.role || "AI Defense Operator"}</span></div>
                    <div><strong>Access Level</strong><span>{currentUser?.access_level || "Administrator"}</span></div>
                  </div>
                  <button className="settings-danger-btn" onClick={handleLogout}>
                    Logout
                  </button>
                </div>

                <div className="panel">
                  <div className="panel-title">
                    <h3>AI Engine Status</h3>
                    <span>Detection module</span>
                  </div>
                  <div className="settings-list">
                    <div><strong>AI Engine</strong><span className="online-text">Online</span></div>
                    <div><strong>Supported Categories</strong><span>5</span></div>
                    <div><strong>AI Defense Score</strong><span>{dashboardTotals.modelAccuracy}</span></div>
                    <div><strong>Optimized Features</strong><span>{dashboardTotals.featuresUsed}</span></div>
                  </div>
                </div>

                <div className="panel">
                  <div className="panel-title">
                    <h3>Platform Health</h3>
                    <span>Live services</span>
                  </div>
                  <div className="settings-list">
                    <div><strong>Backend API</strong><span className="online-text">Running</span></div>
                    <div><strong>Database</strong><span className="online-text">Connected</span></div>
                    <div><strong>Reports Module</strong><span className="online-text">Ready</span></div>
                    <div><strong>Email Reports</strong><span>Configured</span></div>
                  </div>
                </div>
              </div>

              <div className="settings-grid-two">
                <div className="panel">
                  <div className="panel-title">
                    <h3>Notification Preferences</h3>
                    <span>Alert control</span>
                  </div>
                  <div className="toggle-list">
                    <div>
                      <span>Critical attack toast alerts</span>
                      <label className="switch">
                        <input type="checkbox" defaultChecked />
                        <span className="slider"></span>
                      </label>
                    </div>
                    <div>
                      <span>Voice AI assistant</span>
                      <label className="switch">
                        <input
                          type="checkbox"
                          checked={voiceEnabled}
                          onChange={() => setVoiceEnabled((prev) => !prev)}
                        />
                        <span className="slider"></span>
                      </label>
                    </div>
                    <div>
                      <span>Email security reports</span>
                      <label className="switch">
                        <input type="checkbox" defaultChecked />
                        <span className="slider"></span>
                      </label>
                    </div>
                    <div>
                      <span>Live map animation</span>
                      <label className="switch">
                        <input type="checkbox" defaultChecked />
                        <span className="slider"></span>
                      </label>
                    </div>
                  </div>
                </div>

                <div className="panel">
                  <div className="panel-title">
                    <h3>System Information</h3>
                    <span>EvoGuard version</span>
                  </div>
                  <div className="system-info-box">
                    <p><b>Platform:</b> EvoGuard Enterprise</p>
                    <p><b>Version:</b> 1.0 Senior Project Build</p>
                    <p><b>Frontend:</b> React Dashboard</p>
                    <p><b>Backend:</b> Flask API</p>
                    <p><b>Database:</b> SQLite Threat Logs</p>
                    <p><b>AI Mode:</b> Agentic AI Defense Simulation</p>
                  </div>
                </div>
              </div>
            </section>
          )}

          <section className="assistant-grid">
            <div className="panel assistant-panel">
              <div className="panel-title">
                <h3>AI Security Assistant</h3>
                <span>Ask EvoGuard</span>
              </div>
              <div className="assistant-box">
                <input
                  type="text"
                  placeholder="Ask: latest attack, risk, summary, recommend actions..."
                  value={chatQuestion}
                  onChange={(e) => setChatQuestion(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") askAssistant();
                  }}
                />
                <button onClick={askAssistant}>Ask</button>
              </div>
              {chatAnswer && (
                <div className="assistant-answer">
                  <strong>EvoGuard AI:</strong>
                  <p>{chatAnswer}</p>
                </div>
              )}
            </div>
          </section>
        </main>
      </div>
    </>
  );
}

export default App;



