import os
import json

# Define your actual camera locations (Latitude, Longitude)
EDGE_NODES_CONFIG = {
    "ALPHA": {
        "sector": "Sector 4 - Gate Checkpoint",
        "lat": 12.9856,
        "lon": 80.2452,
        "mode": "Tactical Virtual Fence",
        "ip": "192.168.1.101",
        "status": "ONLINE"
    },
    "BRAVO": {
        "sector": "Sector 7 - Perimeter Fence",
        "lat": 12.9890,
        "lon": 80.2490,
        "mode": "Camouflage & Anomaly",
        "ip": "192.168.1.102",
        "status": "ONLINE"
    },
    "CHARLIE": {
        "sector": "Sector 1 - Drone Patrol",
        "lat": 12.9820,
        "lon": 80.2410,
        "mode": "Vector Trajectory",
        "ip": "192.168.1.103",
        "status": "STANDBY"
    }
}

def generate_offline_map(base_dir, output_file="camera_network_map.html"):
    map_path = os.path.join(base_dir, output_file)
    nodes_json = json.dumps(EDGE_NODES_CONFIG)

    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>IBVAP Tactical Edge Map</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <style>
        html, body {{ height: 100%; margin: 0; padding: 0; background: #04070a; color: #00ff66; font-family: monospace; overflow: hidden; }}
        #header {{ height: 45px; padding: 8px 20px; background: #0a0f18; border-bottom: 2px solid #00ff66; display: flex; align-items: center; justify-content: space-between; }}
        #map {{ width: 100%; height: calc(100vh - 65px); background: #0b0f19; }}
        .leaflet-popup-content-wrapper {{ background-color: #111827 !important; color: #00ff66 !important; border: 1px solid #00ff66; border-radius: 4px; font-family: monospace; }}
        .leaflet-popup-tip {{ background-color: #111827 !important; }}
        .nav-back {{ color: #38bdf8; text-decoration: none; font-weight: bold; border: 1px solid #38bdf8; padding: 5px 12px; border-radius: 4px; }}
        .nav-back:hover {{ background: #38bdf8; color: #04070a; }}
    </style>
</head>
<body>
    <div id="header">
        <span><b>IBVAP // SENSOR DEPLOYMENT GRID</b></span>
        <a href="/" class="nav-back">&larr; Return to HQ Dashboard</a>
    </div>
    <div id="map"></div>

    <script>
        var nodeData = {nodes_json};
        
        // Initialize Map
        var map = L.map('map', {{ zoomControl: true }});

        // OpenStreetMap Tile Layer (cached automatically by browser after first load)
        L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
            maxZoom: 19,
            attribution: '© OpenStreetMap'
        }}).addTo(map);

        var markersGroup = L.featureGroup();

        for (var key in nodeData) {{
            var node = nodeData[key];
            var color = (node.status === 'ONLINE') ? '#00ff66' : '#facc15';

            // Pinpoint center marker
            var marker = L.circleMarker([node.lat, node.lon], {{
                radius: 8,
                fillColor: color,
                color: '#ffffff',
                weight: 2,
                opacity: 1,
                fillOpacity: 0.9
            }});

            // 40-meter coverage zone circle
            var coverage = L.circle([node.lat, node.lon], {{
                radius: 40,
                color: color,
                fillColor: color,
                fillOpacity: 0.15,
                weight: 1.5
            }});

            marker.bindPopup(
                "<b>NODE: " + key + "</b><br>" +
                "Sector: " + node.sector + "<br>" +
                "Status: " + node.status + "<br>" +
                "Mode: " + node.mode + "<br>" +
                "LAN IP: " + node.ip + "<br>" +
                "GPS: " + node.lat.toFixed(4) + ", " + node.lon.toFixed(4)
            );

            markersGroup.addLayer(marker);
            markersGroup.addLayer(coverage);
        }}

        markersGroup.addTo(map);

        // Auto-fit bounds tightly around all camera nodes for exact accuracy
        map.fitBounds(markersGroup.getBounds().pad(0.35));
    </script>
</body>
</html>"""

    with open(map_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return map_path