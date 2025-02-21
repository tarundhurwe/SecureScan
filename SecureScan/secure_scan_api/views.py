from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import (
    RegisterSerializer,
    LoginSerializer,
    ScanSerializer,
    ScanResultSerializer,
)
from django.shortcuts import get_object_or_404
from scan.tasks import run_scan
from .models import Scan, ScanResult


class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.save()
            refresh = RefreshToken.for_user(user)

            return Response(
                {
                    "message": "User registered successfully",
                    "access_token": str(refresh.access_token),
                    "refresh_token": str(refresh),
                },
                status=status.HTTP_201_CREATED,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data["user"]
            refresh = RefreshToken.for_user(user)

            return Response(
                {
                    "message": "Login successful",
                    "access_token": str(refresh.access_token),
                    "refresh_token": str(refresh),
                },
                status=status.HTTP_200_OK,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ScanView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = ScanSerializer(data=request.data)
        if serializer.is_valid():
            scan = serializer.save(user=request.user)
            run_scan.delay(scan.id)
            return Response(
                {"scan_id": str(scan.id), "status": scan.status},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, scan_id):
        """
        get scan status
        """
        scan = get_object_or_404(Scan, id=scan_id, user=request.user)
        return Response(
            {"scan_id": str(scan.id), "status": scan.status}, status=status.HTTP_200_OK
        )


class ScanResultsAPIView(APIView):
    """Scan result api"""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, scan_id):
        scan = get_object_or_404(Scan, id=scan_id, user=request.user)
        results = ScanResult.objects.filter(scan=scan)
        serializer = ScanResultSerializer(results, many=True)

        return Response(
            {"scan_id": str(scan.id), "results": serializer.data},
            status=status.HTTP_200_OK,
        )
