# Руководство по реализации Rustcan

## Основная функциональность сканирования

### Реализация сканера
Расположен в `scanner.rs`, модуль сканера предоставляет:
- Асинхронное TCP-сканирование
- Параллельное сканирование портов
- Обработку таймаутов
- Управление ресурсами

### Определение сервисов
Расположен в `service_detection.rs`, реализует:
- Специфичные для протокола зонды
- Сопоставление паттернов ответов
- Определение сервисов
- Определение версий

### Сопоставление паттернов
Расположен в `patterns.rs`, обрабатывает:
- Определение паттернов сканирования
- Анализ ответов
- Идентификацию сервисов
- Определение протоколов

## Ключевые компоненты

### 1. Движок сканера
```rust
pub struct Scanner {
    target: Target,
    ports: PortRange,
    concurrency: usize,
    timeout: Duration,
}
```

Возможности:
- Асинхронное сканирование с Tokio
- Параллельная обработка соединений
- Управление ресурсами
- Отчеты о прогрессе

### 2. Определение сервисов
```rust
pub struct ServiceDetector {
    patterns: Vec<ServicePattern>,
    timeout: Duration,
}
```

Возможности:
- Специфичные для протокола зонды
- Сопоставление паттернов
- Идентификация сервисов
- Определение версий

### 3. DNS-резолвинг
```rust
pub struct DnsResolver {
    resolver: AsyncResolver,
}
```

Возможности:
- Асинхронный DNS-резолвинг
- Валидация имен хостов
- Расширение диапазонов IP
- Обратные DNS-запросы

## Паттерны реализации

### 1. Паттерн Async/Await
```rust
async fn scan_port(&self, target: IpAddr, port: u16) -> Result<ScanResult> {
    let socket = TcpStream::connect((target, port)).await?;
    // ... логика сканирования
}
```

### 2. Параллельное сканирование
```rust
async fn scan_range(&self, targets: Vec<IpAddr>, ports: PortRange) -> Vec<ScanResult> {
    let mut results = Vec::new();
    let semaphore = Arc::new(Semaphore::new(self.concurrency));
    
    for target in targets {
        for port in ports {
            let permit = semaphore.clone().acquire_owned().await?;
            // ... логика сканирования
        }
    }
    results
}
```

### 3. Определение сервисов
```rust
async fn detect_service(&self, target: IpAddr, port: u16) -> Result<ServiceInfo> {
    let mut socket = TcpStream::connect((target, port)).await?;
    // ... логика определения сервисов
}
```

## Обработка ошибок

### 1. Пользовательские типы ошибок
```rust
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("Ошибка соединения: {0}")]
    ConnectionError(#[from] std::io::Error),
    #[error("Таймаут: {0}")]
    TimeoutError(String),
    // ... другие варианты ошибок
}
```

### 2. Распространение ошибок
```rust
async fn scan(&self) -> Result<Vec<ScanResult>> {
    let results = self.scan_range().await?;
    Ok(results)
}
```

## Логирование и мониторинг

### 1. Структурированное логирование
```rust
tracing::info!("Начало сканирования цели: {}", target);
tracing::debug!("Сканирование порта {} на {}", port, target);
```

### 2. Отчеты о прогрессе
```rust
let progress = ProgressBar::new(total_ports as u64);
progress.set_style(ProgressStyle::default_bar()
    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
    .progress_chars("#>-"));
```

## Тестирование

### 1. Модульные тесты
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_port_scan() {
        // ... реализация теста
    }
}
```

### 2. Интеграционные тесты
```rust
#[cfg(test)]
mod integration {
    use super::*;
    
    #[tokio::test]
    async fn test_full_scan() {
        // ... реализация теста
    }
}
```

## Оптимизация производительности

1. **Управление параллелизмом**
   - Ограничение на основе семафоров
   - Управление ресурсами
   - Обработка обратного давления

2. **Управление памятью**
   - Эффективные структуры данных
   - Потоковая обработка
   - Управление буферами

3. **Оптимизация сети**
   - Пул соединений
   - Обработка таймаутов
   - Механизмы повторных попыток 