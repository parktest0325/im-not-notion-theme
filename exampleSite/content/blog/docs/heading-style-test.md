---
title: "Heading Style Test"
date: 2026-03-01
description: "h2, h3, h4 스타일 비교를 위한 테스트 페이지"
tags: ["test"]
weight: 1
showList: true
showMenu: true
---

## 안드로이드 앱 분석 기초

안드로이드 앱의 보안 분석을 수행하기 위해서는 먼저 APK 파일의 구조를 이해하고, 이를 디컴파일하여 소스 코드 수준에서 분석할 수 있어야 한다. 이 글에서는 기본적인 분석 환경 구축부터 실전 분석까지 다룬다.

### APK 구조 이해하기

APK는 기본적으로 ZIP 포맷이며, 내부에 DEX 파일, 리소스, 매니페스트 등이 포함된다.

```
app.apk
├── classes.dex        # Dalvik 바이트코드
├── AndroidManifest.xml
├── res/               # 리소스 파일
├── lib/               # 네이티브 라이브러리 (.so)
└── META-INF/          # 서명 정보
```

네이티브 라이브러리가 포함된 경우, `lib/` 디렉토리 하위에 아키텍처별로 .so 파일이 존재한다.

#### 디컴파일 도구 설정

jadx를 사용하면 DEX를 바로 Java 소스로 변환할 수 있다. 설치 후 간단하게 실행 가능하다.

#### 서명 검증 우회

APK를 수정한 후 다시 서명해야 실행할 수 있다. `apksigner`를 사용하면 된다.

### 동적 분석 환경

정적 분석만으로는 런타임 동작을 파악하기 어렵다. Frida를 사용한 동적 분석 환경을 구축한다.

#### Frida 서버 설치

루팅된 디바이스 또는 에뮬레이터에 Frida 서버를 설치한다. 아키텍처에 맞는 바이너리를 다운로드해야 한다.

#### 후킹 스크립트 작성

Java 메서드를 후킹하여 인자와 리턴값을 확인할 수 있다.

```javascript
Java.perform(function() {
    var MainActivity = Java.use('com.example.app.MainActivity');
    MainActivity.checkPassword.implementation = function(input) {
        console.log('Input: ' + input);
        var result = this.checkPassword(input);
        console.log('Result: ' + result);
        return result;
    };
});
```

## Demand Paging 구현

운영체제에서 메모리 관리는 핵심적인 부분이다. 특히 Demand Paging은 실제로 접근이 발생했을 때만 물리 페이지를 할당하는 기법이다.

### 페이지 폴트 핸들러

페이지 폴트가 발생하면 커널의 핸들러가 호출된다. 핸들러는 해당 가상 주소에 대한 매핑을 확인하고, 필요한 경우 물리 프레임을 할당한다.

#### 스택 영역 처리

스택 영역에서 페이지 폴트가 발생하면, 스택을 확장해야 한다. 현재 스택 포인터와 폴트 주소를 비교하여 유효한 스택 접근인지 판단한다.

#### 힙 영역 처리

힙은 brk/sbrk 시스템콜로 관리된다. 프로세스의 heap 영역 범위 안에서 발생한 폴트라면 새 프레임을 할당한다.

### CoW (Copy on Write)

fork() 호출 시 부모의 모든 페이지를 복사하지 않고 read-only로 공유한다. 쓰기 시도 시 복사가 발생한다.

#### Copy On Write 동작 흐름

1. fork() → 자식 프로세스의 페이지 테이블이 부모와 같은 물리 프레임을 가리킴
2. 두 프로세스 모두 해당 페이지를 read-only로 설정
3. 어느 쪽이든 쓰기 시도 → 페이지 폴트 발생
4. 핸들러가 새 프레임을 할당하고 내용 복사
5. 쓰기를 시도한 프로세스의 페이지 테이블만 새 프레임으로 갱신

#### TLB 관리

페이지 테이블을 수정한 후에는 반드시 TLB를 무효화해야 한다. 그렇지 않으면 stale 매핑으로 인한 버그가 발생한다.

## Frida를 활용한 SSL Pinning 우회

HTTPS 통신을 분석하려면 SSL Pinning을 우회해야 한다. 앱이 특정 인증서만 신뢰하도록 고정(pin)해놓기 때문에 중간자(MITM) 프록시가 차단된다.

### 일반적인 우회 기법

대부분의 앱은 OkHttp, TrustManager, 또는 네이티브 레벨에서 pinning을 구현한다. 각각 우회 방법이 다르다.

#### OkHttp CertificatePinner

가장 흔한 패턴이다. OkHttp의 `CertificatePinner.check` 메서드를 후킹하면 된다.

```javascript
Java.perform(function() {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
        console.log('[+] Bypassing SSL Pinning for: ' + hostname);
        return;
    };
});
```

#### X509TrustManager 커스텀 구현

앱이 자체 TrustManager를 구현한 경우, `checkServerTrusted`를 빈 함수로 대체한다.

### 네이티브 레벨 Pinning

일부 보안 솔루션은 Java 레이어가 아닌 네이티브(.so) 레벨에서 인증서를 검증한다. 이 경우 `libssl.so`의 `SSL_CTX_set_verify` 함수를 후킹해야 한다.

#### libssl 후킹 방법

`Module.findExportByName`으로 심볼을 찾고, `Interceptor.attach`로 콜백을 교체한다. verify 콜백의 리턴값을 항상 성공으로 바꾸면 우회된다.
