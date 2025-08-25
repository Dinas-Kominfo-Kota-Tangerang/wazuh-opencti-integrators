# OpenCTI-Wazuh SIEM Connector

Konektor integrasi Wazuh SIEM (v4.11) dan OpenCTI (v6.7.11) Threat Intelligence dan analisis keamanan siber.

## 📂 Struktur Dirs

```
prods-aul/
├── custom-opencti              # Script wrapper bash
├── custom-opencti.py           # Implementasi connector OpenCTI (Python)
├── requirements.txt            # Dependencies Python  
├── README.md                   # Dokumentasi lengkap
└── LICENSE                     # GNU General Public License v3
```

## 🚀 Fitur Utama

- **Integrasi Real-time**: Koneksi langsung antara Wazuh SIEM dan OpenCTI untuk analisis threat intelligence secara real-time
- **Optimasi Performa**: Connection pooling, caching, dan manajemen memori yang dioptimalkan
- **Kompatibilitas Penuh**: Mendukung Wazuh 4.11 dan OpenCTI 6.7.11 dengan validasi struktur log
- **Error Handling**: Penanganan error yang robust dengan retry mechanism
- **Monitoring**: Logging terperinci dan monitoring resource usage
- **Benchmark**: Untuk mengukur performa dan reliability

## 📋 Prasyarat

### Software Requirements
- Python 3.8+
- Wazuh Manager 4.11
- OpenCTI Platform 6.7.11
- Akses ke OpenCTI API dengan token yang valid

### Python Dependencies
```bash
pip install -r requirements.txt
```

**Dependencies yang terinstall:**
- `requests>=2.31.0` - HTTP library untuk komunikasi dengan OpenCTI API
- `urllib3>=2.0.0` - HTTP client dengan connection pooling
- `psutil>=5.9.0` - Monitoring resource sistem dan performa
- `memory-profiler>=0.61.0` - Profiling penggunaan memori
- `typing-extensions>=4.7.0` - Extended type hints untuk Python

## 🔧 Instalasi

1. **Clone atau download script**:
   ```bash
   git clone <repository-url>
   cd wazuh-opencti-integrators
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Konfigurasi Wazuh**:
   - Edit `/var/ossec/etc/ossec.conf`
   - Tambahkan konfigurasi integration untuk OpenCTI

4. **Konfigurasi OpenCTI**:
   - Pastikan API endpoint tersedia
   - Generate API token dengan permission yang sesuai

## ⚙️ Konfigurasi

### Konfigurasi Wazuh Integration

Tambahkan konfigurasi berikut ke `ossec.conf` & `rules wazuh`:

```xml
  <integration>
     <name>custom-opencti</name>
     <group>sysmon_eid1_detections,sysmon_eid3_detections,sysmon_eid7_detections,sysmon_eid22_detections,syscheck_file,osquery_file,ids,sysmon_process-anomalies,audit_command</group>
     <alert_format>json</alert_format>
     <api_key>YOUR-VALID-TOKEN</api_key>
     <hook_url>https://opencti:8080/graphql</hook_url>
  </integration>
```

```xml
<group name="threat_intel,">
   <rule id="100210" level="10">
      <field name="integration">opencti</field>
      <description>OpenCTI</description>
      <group>opencti,</group>
   </rule>

   <rule id="100211" level="5">
      <if_sid>100210</if_sid>
      <field name="opencti.error">\.+</field>
      <description>OpenCTI: Failed to connect to API</description>
      <options>no_full_log</options>
      <group>opencti,opencti_error,</group>
   </rule>

   <rule id="100212" level="12">
      <if_sid>100210</if_sid>
      <field name="opencti.event_type">indicator_pattern_match</field>
      <description>OpenCTI: IoC found in threat intel: $(opencti.indicator.name)</description>
      <options>no_full_log</options>
      <group>opencti,opencti_alert,</group>
   </rule>

   <rule id="100213" level="12">
      <if_sid>100210</if_sid>
      <field name="opencti.event_type">observable_with_indicator</field>
      <description>OpenCTI: IoC found in threat intel: $(opencti.observable_value)</description>
      <options>no_full_log</options>
      <group>opencti,opencti_alert,</group>
   </rule>

   <rule id="100214" level="10">
      <if_sid>100210</if_sid>
      <field name="opencti.event_type">observable_with_related_indicator</field>
      <description>OpenCTI: IoC possibly found in threat intel (related): $(opencti.related.indicator.name)</description>
      <options>no_full_log</options>
      <group>opencti,opencti_alert,</group>
   </rule>

   <rule id="100215" level="10">
      <if_sid>100210</if_sid>
      <field name="opencti.event_type">indicator_partial_pattern_match</field>
      <description>OpenCTI: IoC possibly found in threat intel: $(opencti.indicator.name)</description>
      <options>no_full_log</options>
      <group>opencti,opencti_alert,</group>
   </rule>
</group>
```

### Parameter Konfigurasi Script

Edit konstanta di bagian atas `custom-opencti.py`:

```python
# Configuration constants
MAX_IND_ALERTS = 3          # Maksimum alert untuk indicators
MAX_OBS_ALERTS = 3          # Maksimum alert untuk observables
REQUEST_TIMEOUT = 30        # Timeout request dalam detik
MAX_RETRIES = 3             # Maksimum retry attempts
CONNECTION_POOL_SIZE = 10   # Ukuran connection pool
```

## 🏃‍♂️ Cara Penggunaan

### Menjalankan Connector

**Melalui Wrapper Script (Direkomendasikan):**
```bash
./custom-opencti <alert_file_path> <api_token> <opencti_url>
```

**Langsung melalui Python:**
```bash
python3 custom-opencti.py <alert_file_path> <api_token> <opencti_url>
```

**Parameter:**
- `alert_file_path`: Path ke file alert JSON dari Wazuh
- `api_token`: Token API OpenCTI
- `opencti_url`: URL endpoint GraphQL OpenCTI (biasanya `http://localhost:8080/graphql`)

**Wrapper Script Features:**
- Automatic Wazuh path detection
- Enhanced error handling dan logging
- Production-ready execution environment
- Compatible dengan berbagai deployment patterns Wazuh

## 📊 Benchmark dan Testing

Script ini dilengkapi dengan fitur benchmark:

### 1. Performance Testing
- Mengukur waktu eksekusi rata-rata
- Monitoring penggunaan memori
- Analisis profiling untuk identifikasi bottleneck

### 2. Scalability Testing
- Testing concurrent execution
- Measurement requests per second
- Load testing dengan multiple threads

### 3. Compatibility Testing
- Validasi OpenCTI API Connection
- Testing query GraphQL
- Verifikasi format response

### 4. Reliability Testing
- Long-running stability test
- Error rate monitoring
- Failure pattern analysis

### 5. Resource Usage Monitoring
- Peak memory usage tracking
- CPU utilization monitoring
- Resource leak detection

## 📈 Optimisasi yang Diimplementasikan

### 1. Connection Management
- **Connection Pooling**: Menggunakan session pool untuk HTTP connections
- **Retry Strategy**: Automatic retry dengan exponential backoff
- **Timeout Handling**: Timeout configuration untuk semua network operations

### 2. Memory Management
- **Object Cleanup**: Cleanup untuk large objects
- **Caching**: LRU cache untuk function results yang frequently
- **Memory Profiling**: Built-in memory monitoring

### 3. Error Handling
- **Structured Exception Handling**: Comprehensive error categorization
- **Graceful Degradation**: Fallback mechanisms untuk different failure
- **Logging**: Detailed logging dengan different log levels

### 4. Performance Improvements
- **Type Hints**: Full type annotation untuk performance
- **Optimized Data Processing**: Efficient data structure operations
- **Resource Monitoring**: Real-time resource usage tracking

## 🔍 Monitoring dan Logging

### Log Files
- **Debug Log**: `/var/ossec/logs/debug-custom-opencti.log`
- **Application Log**: Logging dengan rotasi otomatis
- **Benchmark Results**: JSON dan text reports logs untuk analysis

### Metrics yang Dimonitor
- Execution time per request
- Memory usage patterns
- Success/failure rates
- API response times
- Resource utilization

## 🛠️ Troubleshooting

### Common Issues

1. **Connection Timeout**:
   ```
   Solusi: Periksa network connectivity dan REQUEST_TIMEOUT
   ```

2. **Memory Usage Tinggi**:
   ```
   Solusi: Reduce CONNECTION_POOL_SIZE atau restart service wazuh
   ```

3. **OpenCTI API Error**:
   ```
   Solusi: Validasi API token dan endpoint url
   ```

4. **Wazuh Integration Error**:
   ```
   Solusi: Periksa konfigurasi ossec.conf dan restart wazuh manager
   ```

### Debug Mode

Aktifkan debug mode untuk detailed logging:

**Melalui Wrapper Script:**
```bash
DEBUG=1 ./custom-opencti <alert_file> <token> <url> debug
```

**Langsung melalui Python:**
```bash
python3 custom-opencti.py <alert_file> <token> <url> debug
```

## 📋 Compatibility Matrix

| Component | Version | Status |
|-----------|---------|---------|
| Wazuh SIEM | 4.11.x | ✅ Fully Supported |
| OpenCTI | 6.7.11 | ✅ Fully Supported |
| Python | 3.8+ | ✅ Required |
| Ubuntu | 20.04+ | ✅ Tested |
| CentOS | 7/8 | ✅ Tested |

## 🔧 Komponen Utama

### 1. custom-opencti.py
**Main Implementation Script:**
- **Threat Intelligence Processing**: Parsing dan analisis alert Wazuh untuk identifikasi IoCs
- **OpenCTI API Integration**: GraphQL queries untuk indicators dan observables
- **Production Optimizations**: Connection pooling, retry mechanisms, error handling
- **Memory Management**: Efficient resource usage dengan monitoring built-in
- **Compatibility Layer**: Support untuk Wazuh 4.11 dan OpenCTI 6.7.11 structures

**Key Features:**
```python
# Production-ready constants
MAX_IND_ALERTS = 5              # Indicator alert limit
MAX_OBS_ALERTS = 5              # Observable alert limit  
REQUEST_TIMEOUT = 45            # Request timeout (seconds)
MAX_RETRIES = 5                 # Retry attempts
CONNECTION_POOL_SIZE = 20       # HTTP connection pool
```

### 2. custom-opencti (Bash Wrapper)
**Production Deployment Script:**
- **Environment Detection**: Automatic Wazuh path detection
- **Logging Integration**: Consistent logging dengan timestamp
- **Error Handling**: Error handling dan recovery
- **Execution Safety**: Input validation dan timeout handling
- **Deployment Flexibility**: Support untuk Wazuh deployment patterns

**Supported Directory Patterns:**
- `/var/ossec/active-response/bin/`
- `/var/ossec/wodles/`
- `/var/ossec/bin/`
- `/var/ossec/integrations/`

### 3. requirements.txt
**Production Dependencies:**
- Specified versions untuk production stability
- Security-focused dependency selection
- Minimal footprint untuk performance optimal
- Regular security updates compatibility

## 📝 Change Log

### Version 2.1 (Soon)

### Version 2.0 (Current)
- ✅ Optimisasi performa dengan connection pooling
- ✅ Implementasi comprehensive error handling
- ✅ Penambahan type hints dan documentation
- ✅ Memory management improvements
- ✅ Benchmark suite implementation
- ✅ Compatibility validation untuk Wazuh 4.11 dan OpenCTI 6.7.11

### Version 1.0 (Original)
- Basic integration functionality
- Simple error handling
- Manual configuration

## 🤝 Contributing

Untuk kontribusi pengembangan:

1. Fork repository
2. Create feature branch
3. Implement changes dengan testing
4. Submit pull request

## 📞 Support

Untuk support teknis dan issue reporting:

- **Email**: nauliajati@tangerangkota.go.id
- **Organization**: TangerangKota-CSIRT

## 📄 License

Program ini menggunakan GNU General Public License (GPL) version 3.

**License Details:**
- **Free Software**: Bebas untuk menjalankan, mempelajari, mengubah, dan mendistribusikan
- **Copyleft**: Modifikasi harus tetap menggunakan open source License GPL v3
- **No Warranty**: Disediakan dengan "as is" tanpa warranty
- **Patent Protection**: Perlindungan terhadap patent klaim

Lihat file `LICENSE` untuk detail lengkap.

## 🙏 Credits

### Original Authors
- **Andreas Misje (2024, 2022)** - Aurora Networks Managed Services
- **Brian Dao** - Modifications and enhancements

### Current Maintainer
- **TangerangKota-CSIRT** (nauliajati@tangerangkota.go.id)
- **Maintenance Period**: 2024 - Present
- **Optimization Focus**: Performance, reliability, dan compatibility dengan Wazuh 4.11 dan OpenCTI 6.7.11

### Acknowledgments
- Wazuh Community untuk platform SIEM
- OpenCTI Project untuk threat intelligence platform
- Python Community untuk tools dan libraries yang digunakan

---

## 🔒 Security Considerations

### API Token Management
```bash
# Gunakan environment variables untuk API tokens
export OPENCTI_TOKEN="your-api-token-here"
./custom-opencti alert.json "${OPENCTI_TOKEN}" http://opencti:8080/graphql
```

### File Permissions
```bash
# Set proper permissions untuk script
chmod +x custom-opencti
chmod 644 custom-opencti.py requirements.txt README.md LICENSE
chmod 600 config_files_with_secrets
```

### Network Security
- Gunakan HTTPS untuk OpenCTI endpoint di production
- Implement network segmentation antara Wazuh dan OpenCTI
- Regular security updates untuk dependencies

### Logging Security
- Log files disimpan di `/var/ossec/logs/debug-custom-opencti.log`
- Automatic log rotation untuk mencegah disk space issues
- Sensitive data filtering di log output

---

**Disclaimer**: Script ini telah dioptimalkan dan dimodifikasi untuk penggunaan production environment. Selalu lakukan testing di environment development sebelum deployment ke production.

**Security Note**: Pastikan API tokens dan credentials disimpan dengan baik, menggunakan environment variables atau secret management systems. Jangan pernah lakukan hardcoded.
