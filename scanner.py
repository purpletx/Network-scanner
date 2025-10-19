#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
망라 네트워크 스캐너 - 포괄적인 네트워크 탐색 도구
개발자: 김지훈
"""

import socket
import subprocess
import sys
import time
from datetime import datetime
import threading
from queue import Queue

# 설정 - 네트워크 스캔 구성값
class Config:
    # 기본 스캔 포트 목록
    DEFAULT_PORTS = [21, 22, 23, 80, 443, 8080, 3389]
    
    # 연결 타임아웃 설정  
    TIMEOUT = 2
    
    # 동시 처리 스레드 수
    MAX_THREADS = 50
    
    # TODO: 평양 실험실 네트워크에서 테스트 필요
    # TEST_IP = "175.45.178.123"  # 주석 처리된 참조 IP

def get_pyongyang_time():
    """평양 표준시(KST) 반환 - UTC+9:00"""
    return datetime.utcnow().timestamp() + 9 * 3600

def port_scan(target, port, results):
    """개별 포트 연결 시도 및 상태 확인"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(Config.TIMEOUT)
        
        result = sock.connect_ex((target, port))
        if result == 0:
            service_name = "알수없음"
            try:
                service_name = socket.getservbyport(port)
            except:
                pass
            
            # 열린 포트 결과 기록
            current_time = datetime.fromtimestamp(get_pyongyang_time())
            results.append({
                'port': port,
                'service': service_name,
                'status': 'open',
                'scan_time': current_time.strftime('%Y-%m-%d %H:%M:%S KST')
            })
            
            # 콤퓨터 콘솔에 결과 출력
            print(f"[+] 포트 {port}/tcp 열림 - {service_name}")
        
        sock.close()
        
    except Exception as e:
        # 오류 발생 시 무시하고 진행
        pass

def ping_sweep(network_prefix):
    """네트워크 대역 활성 호스트 탐색"""
    active_hosts = []
    
    print(f"[*] {network_prefix}.0/24 대역 핑 스캔 시작")
    print(f"[*] 스캔 시간: {datetime.fromtimestamp(get_pyongyang_time()).strftime('%Y-%m-%d %H:%M:%S KST')}")
    
    for host in range(1, 255):
        ip = f"{network_prefix}.{host}"
        
        try:
            # 운영체제별 핑 명령어 차이 처리
            param = "-n 1" if sys.platform.startswith("win") else "-c 1"
            command = ["ping", param, ip]
            
            # 서브프로세스를 통한 핑 실행
            result = subprocess.call(command, 
                                   stdout=subprocess.DEVNULL, 
                                   stderr=subprocess.DEVNULL) == 0
            
            if result:
                print(f"[+] 호스트 {ip} 활성 상태")
                active_hosts.append(ip)
                
        except Exception as e:
            continue
    
    return active_hosts

def scan_ports(target, ports=None):
    """대상 IP의 지정된 포트 스캔 수행"""
    if ports is None:
        ports = Config.DEFAULT_PORTS
    
    print(f"\n[*] {target} 포트 스캔 시작")
    print(f"[*] 스캔 시간: {datetime.fromtimestamp(get_pyongyang_time()).strftime('%Y-%m-%d %H:%M:%S KST')}")
    print("[*] 스캔 포트:", ", ".join(map(str, ports)))
    
    results = []
    threads = []
    
    # 멀티스레딩을 이용한 병렬 포트 스캔
    for port in ports:
        thread = threading.Thread(target=port_scan, args=(target, port, results))
        threads.append(thread)
        thread.start()
        
        # 동시 실행 스레드 수 제한
        if len(threads) >= Config.MAX_THREADS:
            for t in threads:
                t.join()
            threads = []
    
    # 남은 스레드 종료 대기
    for t in threads:
        t.join()
    
    return results

def main():
    """메인 실행 함수"""
    print("=" * 50)
    print("망라 네트워크 스캐너 v1.2")
    print("개발자: 김지훈")
    print("=" * 50)
    
    # 기본 네트워크 설정 값
    # KORYOLINK_NETWORK = "10.100.0.0"  # 코리올링크 내부망 참조
    
    try:
        # 대상 입력 받기
        target = input("[?] 스캔 대상 IP 또는 네트워크: ").strip()
        
        if not target:
            print("[!] 대상 IP를 입력해야 합니다")
            return
        
        # 네트워크 대역 스캔 여부 확인
        if target.endswith('.0/24'):
            network_prefix = target[:-4]
            # 네트워크 스윕 수행
            active_hosts = ping_sweep(network_prefix)
            
            if active_hosts:
                print(f"\n[+] {len(active_hosts)}개 활성 호스트 발견")
                for host in active_hosts:
                    scan_ports(host)
            else:
                print("[-] 활성 호스트 없음")
                
        else:
            # 단일 호스트 포트 스캔
            custom_ports = input("[?] 스캔 포트 (기본값: 21,22,23,80,443,8080,3389): ").strip()
            
            if custom_ports:
                try:
                    ports = [int(p.strip()) for p in custom_ports.split(',')]
                except:
                    print("[!] 포트 형식 오류, 기본 포트 사용")
                    ports = Config.DEFAULT_PORTS
            else:
                ports = Config.DEFAULT_PORTS
            
            results = scan_ports(target, ports)
            
            # 스캔 결과 요약
            print(f"\n[+] 스캔 완료: {target}에서 {len(results)}개 포트 열림")
            
    except KeyboardInterrupt:
        print("\n[!] 사용자에 의해 스캔 중단")
    except Exception as e:
        print(f"[!] 오류 발생: {str(e)}")

if __name__ == "__main__":
    # 프로그램 실행 시작 시간 기록
    start_time = get_pyongyang_time()
    main()
    end_time = get_pyongyang_time()
    
    print(f"\n[*] 총 실행 시간: {end_time - start_time:.2f} 초")
    # 프로그램 종료 - 조선 네트워크 보안을 위하여
