from django.contrib.auth.models import User
from rest_framework import serializers
from .models import UserProfile, Scan, ScanResult
from django.contrib.auth import authenticate


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=6)

    class Meta:
        model = User
        fields = ["username", "email", "password"]

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("This username is already taken.")
        return value

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already registered.")
        return value

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data["username"],
            email=validated_data["email"],
            password=validated_data["password"],
        )
        UserProfile.objects.create(user=user)  # Create linked profile
        return user


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        username = data.get("username")
        password = data.get("password")

        user = authenticate(username=username, password=password)
        if not user:
            raise serializers.ValidationError("Invalid username or password")

        data["user"] = user
        return data


class ScanSerializer(serializers.ModelSerializer):
    scan_type = serializers.ChoiceField(choices=["nikto", "nmap", "all"], default="all")

    class Meta:
        model = Scan
        fields = ["url", "scan_type"]

    def create(self, validated_data):
        """
        Create a new scan instance with the provided data.
        """
        return Scan.objects.create(**validated_data)

    def validate_url(self, value):
        """
        Validate the target URL format.
        """
        if not value.startswith(("http://", "https://")):
            raise serializers.ValidationError("URL must start with http:// or https://")
        return value


class ScanResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanResult
        fields = ["vulnerability", "severity", "description", "recommendation"]
