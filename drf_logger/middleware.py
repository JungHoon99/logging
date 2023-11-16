from time import time
import socket
import logging
import json
from django.utils.deprecation import MiddlewareMixin
from rest_framework.utils.serializer_helpers import ReturnDict, ReturnList

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

        except Exception as e:
            # 예외가 발생한 경우 로그를 남기고 계속 진행
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

        except Exception as e:
            logger.critical(f"An error occurred: {e}")

        return response

    # 실제 클라이언트에 ip를 가져오는 코드
    # 참고 자료 - https://velog.io/@emrrbs9090/Django-Request-header%EB%A5%BC-%ED%86%B5%ED%95%9C-%ED%81%B4%EB%9D%BC%EC%9D%B4%EC%96%B8%ED%8A%B8-%EC%A0%95%EB%B3%B4-%ED%8C%8C%EC%95%85%ED%95%98%EA%B8%B0
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')

        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip