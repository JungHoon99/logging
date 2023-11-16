from rest_framework import viewsets

from users.serializers import MovieSerializer
from users.models import Movie
from drf_logger.mixins import RequestLogViewMixin

class MovieViewSet(RequestLogViewMixin, viewsets.ModelViewSet):
    queryset = Movie.objects.all()
    serializer_class = MovieSerializer