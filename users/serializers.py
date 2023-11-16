from rest_framework import serializers
from users.models import Movie

class MovieSerializer(serializers.ModelSerializer):
    class Meta:
        model = Movie # 모델 설정
        fields = ('id','title','genre','year') # 필드 설정