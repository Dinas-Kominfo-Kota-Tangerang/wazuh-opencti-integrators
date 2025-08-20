# OpenCTI-Wazuh SIEM Connector

Konektor terintegrasi antara Wazuh SIEM versi 4.11 dan OpenCTI versi 6.7.11 untuk threat intelligence dan analisis keamanan siber yang optimal.

## 🚀 Fitur Utama

- **Integrasi Real-time**: Koneksi langsung antara Wazuh SIEM dan OpenCTI untuk analisis threat intelligence secara real-time
- **Optimasi Performa**: Connection pooling, caching, dan manajemen memori yang dioptimalkan
- **Kompatibilitas Penuh**: Mendukung Wazuh 4.11 dan OpenCTI 6.7.11 dengan validasi struktur log
- **Error Handling**: Penanganan error yang robust dengan retry mechanism
- **Monitoring**: Logging terperinci dan monitoring resource usage
- **Benchmark Suite**: Tools komprehensif untuk mengukur performa dan reliability

## 📋 Prasyarat

### Software Requirements
- Python 3.8+
- Wazuh Manager 4.11
- OpenCTI Platform 6.7.11
- Akses ke OpenCTI API dengan token yang valid

### Python Dependencies
```bash
pip install requests urllib3 psutil memory-profiler typing-extensions
```

## 🔧 Instalasi

1. **Clone atau download script**:
   ```bash
   git clone <repository-url>
   cd opencti-python
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

Tambahkan konfigurasi berikut ke `ossec.conf`:

```xml
<integration>
    <name>opencti</name>
    <hook_url>http://localhost:13000/</hook_url>
    <api_key>YOUR_OPENCTI_API_TOKEN</api_key>
    <alert_format>json</alert_format>
</integration>
```

### Parameter Konfigurasi Script

Edit konstanta di bagian atas `sc-1.py`:

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

```bash
python3 sc-1.py <alert_file_path> <api_token> <opencti_url>
```

**Parameter:**
- `alert_file_path`: Path ke file alert JSON dari Wazuh
- `api_token`: Token API OpenCTI
- `opencti_url`: URL endpoint GraphQL OpenCTI (biasanya `http://localhost:8080/graphql`)

### Menjalankan Benchmark

```bash
python3 benchmark_opencti.py sc-1.py <opencti_url> <api_token>
```

## 📊 Benchmark dan Testing

Script ini dilengkapi dengan suite benchmark komprehensif yang melakukan:

### 1. Performance Testing
- Mengukur waktu eksekusi rata-rata
- Monitoring penggunaan memori
- Analisis profiling untuk identifikasi bottleneck

### 2. Scalability Testing
- Testing concurrent execution
- Measurement requests per second
- Load testing dengan multiple threads

### 3. Compatibility Testing
- Validasi konektivitas OpenCTI API
- Testing struktur query GraphQL
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
- **Timeout Handling**: Proper timeout configuration untuk semua network operations

### 2. Memory Management
- **Object Cleanup**: Proper cleanup untuk large objects
- **Caching**: LRU cache untuk function results yang frequently used
- **Memory Profiling**: Built-in memory monitoring

### 3. Error Handling
- **Structured Exception Handling**: Comprehensive error categorization
- **Graceful Degradation**: Fallback mechanisms untuk different failure scenarios
- **Logging**: Detailed logging dengan different log levels

### 4. Performance Improvements
- **Type Hints**: Full type annotation untuk better performance
- **Optimized Data Processing**: Efficient data structure operations
- **Resource Monitoring**: Real-time resource usage tracking

## 🔍 Monitoring dan Logging

### Log Files
- **Debug Log**: `/var/ossec/logs/debug-custom-opencti.log`
- **Application Log**: Structured logging dengan rotasi otomatis
- **Benchmark Results**: JSON dan text reports untuk analysis

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
   Solusi: Periksa network connectivity dan increase REQUEST_TIMEOUT
   ```

2. **Memory Usage Tinggi**:
   ```
   Solusi: Reduce CONNECTION_POOL_SIZE atau restart service secara berkala
   ```

3. **OpenCTI API Error**:
   ```
   Solusi: Validasi API token dan endpoint URL
   ```

4. **Wazuh Integration Error**:
   ```
   Solusi: Periksa konfigurasi ossec.conf dan restart wazuh-manager
   ```

### Debug Mode

Aktifkan debug mode untuk detailed logging:
```bash
python3 sc-1.py <alert_file> <token> <url> debug
```

## 📋 Compatibility Matrix

| Component | Version | Status |
|-----------|---------|---------|
| Wazuh SIEM | 4.11.x | ✅ Fully Supported |
| OpenCTI | 6.7.11 | ✅ Fully Supported |
| Python | 3.8+ | ✅ Required |
| Ubuntu | 20.04+ | ✅ Tested |
| CentOS | 7/8 | ✅ Tested |

## 🔬 Scientific Methodology

Benchmark menggunakan metodologi ilmiah dengan:

### Statistical Analysis
- **Central Tendency**: Mean, median, mode calculations
- **Variability**: Standard deviation, variance analysis
- **Distribution**: Performance distribution analysis

### Experimental Design
- **Controlled Variables**: Consistent test environment
- **Multiple Iterations**: Statistical significance testing
- **Randomization**: Random test case generation

### Validation Criteria
- **Repeatability**: Consistent results across runs
- **Reliability**: Error rate < 5%
- **Performance**: Response time < 2 seconds average

## 📝 Change Log

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
3. Implement changes dengan proper testing
4. Submit pull request dengan documentation

## 📞 Support

Untuk support teknis dan issue reporting:

- **Email**: nauliajati@tangerangkota.go.id
- **Organization**: TangerangKota-CSIRT
- **Response Time**: 1-2 business days

## 📄 License

Program ini menggunakan GNU General Public License (GPL) version 3.

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

**Disclaimer**: Script ini telah dioptimalkan dan dimodifikasi untuk penggunaan production environment. Selalu lakukan testing di environment development sebelum deployment ke production.

**Security Note**: Pastikan API tokens dan credentials disimpan dengan aman dan tidak di-commit ke version control system.
