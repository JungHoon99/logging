from time import time
import socket
import logging
import json
from django.utils.deprecation import MiddlewareMixin
from rest_framework.utils.serializer_helpers import ReturnDict, ReturnList

import threading
import boto3
from botocore.exceptions import NoCredentialsError
import os

logger = logging.getLogger(__name__)

logger.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# 파일 핸들러를 추가 (ThreadHandler 사용)
file_handler = logging.FileHandler('app.log')  # 파일명은 적절히 변경

file_handler.setFormatter(formatter)
file_handler.setLevel(logging.INFO)

logger.addHandler(file_handler)

RESPONSE_DATA_CHECK={
    ReturnList,
    ReturnDict,
}

ERROR_RESPONSE_STATUS = "500"
LEVEL_INFO = "INFO"
LEVEL_ERROR = "ERROR"

AWS_ACCESS_KEY = os.environ.get('AWS_ACCESS_KEY')
AWS_SECREAT_KEY = os.environ.get('AWS_SECRET_KEY')
AWS_REGION = os.environ.get('AWS_REGION')

AWS_CLOUD_WATCH_LOG_GROUP=os.environ.get("AWS_CLOUD_WATCH_LOG_GROUP")
AWS_CLOUD_WATCH_LOG_STREAM=os.environ.get("AWS_CLOUD_WATCH_LOG_STREAM")

class RequestLogMiddleware(MiddlewareMixin):
    def process_request(self, request):
        request.start_time = time()

    def process_exception(self, request, exception):
        log_data = {
            'remote_address': self.get_client_ip(request),
            'server_hostname': str(socket.gethostname()),

            'request_method': str(request.method),
            'request_path': str(request.get_full_path()),
            'request_body': json.dumps(request.POST, ensure_ascii=False).replace('"', "'"),

            'response_status': ERROR_RESPONSE_STATUS,
            'An exception occurred': str(exception),

            'run_time': float(time() - request.start_time),
        }
        try:
            log_message = json.dumps(log_data, ensure_ascii=False)
            log_message = f"{log_message}"
            logger.info(log_message)
            thread = threading.Thread(target=self.send_log_to_cloudwatch, args=(log_message, LEVEL_INFO))
            thread.start()

        except Exception as e:
            # 예외가 발생한 경우 로그를 남기고 계속 진행
            thread = threading.Thread(target=self.send_log_to_cloudwatch, args=(f"An error occurred: {e}", LEVEL_ERROR))
            thread.start()
            logger.critical(f"An error occurred: {e}")
        
        raise exception

    def process_response(self, request, response):
        if type(response.data) not in RESPONSE_DATA_CHECK:
            response.data = "<<<Not JSON>>>"
        
        log_data = {
            'remote_address': self.get_client_ip(request),
            'server_hostname': str(socket.gethostname()),

            'request_method': str(request.method),
            'request_path': str(request.get_full_path()),
            'request_body': json.dumps(request.POST, ensure_ascii=False).replace('"', "'"),

            'response_status': str(response.status_code),
            'response_body': json.dumps(response.data, ensure_ascii=False).replace('"', "'"),

            'run_time': float(time() - request.start_time),
        }
        try:
            log_message = json.dumps(log_data, ensure_ascii=False)
            log_message = f"{log_message}"
            logger.info(log_message)
            thread = threading.Thread(target=self.send_log_to_cloudwatch, args=(log_message, LEVEL_INFO))
            thread.start()

        except Exception as e:
            # 예외가 발생한 경우 로그를 남기고 계속 진행
            thread = threading.Thread(target=self.send_log_to_cloudwatch, args=(f"An error occurred: {e}", 'ERROR'))
            thread.start()
            logger.critical(f"An error occurred: {e}")

        return response
    
    def send_log_to_cloudwatch(self, log_message, log_level):
        log_group = AWS_CLOUD_WATCH_LOG_GROUP
        log_stream = AWS_CLOUD_WATCH_LOG_STREAM
        region_name = AWS_REGION

        try:
            # AWS CloudWatch 로그 그룹 및 스트림 생성
            cloudwatch_logs = boto3.client('logs', region_name=region_name, aws_access_key_id=AWS_ACCESS_KEY,
                      aws_secret_access_key=AWS_SECREAT_KEY)

            # AWS CloudWatch에 로그 전송
            cloudwatch_logs.put_log_events(
                logGroupName=log_group,
                logStreamName=log_stream,
                logEvents=[
                    {
                        'timestamp': int(round(time() * 1000)),
                        'message': f"{log_level} - {log_message}",
                    },
                ]
            )
            
        except NoCredentialsError:
            logger.critical('AWS credentials not available')

    # 실제 클라이언트에 ip를 가져오는 코드
    # 참고 자료 - https://velog.io/@emrrbs9090/Django-Request-header%EB%A5%BC-%ED%86%B5%ED%95%9C-%ED%81%B4%EB%9D%BC%EC%9D%B4%EC%96%B8%ED%8A%B8-%EC%A0%95%EB%B3%B4-%ED%8C%8C%EC%95%85%ED%95%98%EA%B8%B0
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')

        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip