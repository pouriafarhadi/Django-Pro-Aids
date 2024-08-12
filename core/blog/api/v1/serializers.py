from django.urls import reverse
from rest_framework import serializers
from ...models import Post, Category
from accounts.models import Profile


# using serializers with custom fields and methods.
# class PostSerializer(serializers.Serializer):
#     id = serializers.IntegerField()
#     title = serializers.CharField(max_length=255)


class CategorySerializer(serializers.ModelSerializer):
    """
    serializes the Category table
    """

    class Meta:
        model = Category
        fields = ["id", "name"]


class PostSerializer(serializers.ModelSerializer):
    """
    serializes the Post table
    """

    snippet = serializers.ReadOnlyField(source="get_snippet")
    relative_url = serializers.URLField(source="get_absolute_api_url", read_only=True)
    absolute_url = serializers.SerializerMethodField(method_name="get_abs_url")

    class Meta:
        model = Post
        fields = [
            "id",
            "author",
            "image",
            "title",
            "content",
            "snippet",
            "category",
            "status",
            "relative_url",
            "absolute_url",
            "created_date",
            "published_date",
        ]
        read_only_fields = [
            "author"
        ]  # because it should be set automatically using request object

    def get_abs_url(self, obj):
        """
        get absolute url of object using reverse
        """
        abs_url = reverse("blog:api-v1:post-detail", kwargs={"pk": obj.id})
        request = self.context.get("request")
        return request.build_absolute_uri(abs_url)

    def to_representation(self, instance):
        """
        to separate representation of object's attributes in list and single object page.
        """
        request = self.context.get("request")
        rep = super().to_representation(instance)
        if request.parser_context.get("kwargs").get("pk"):
            rep.pop("snippet", None)
            rep.pop("relative_url", None)
            rep.pop("absolute_url", None)
        else:
            rep.pop("content", None)
        rep["category"] = CategorySerializer(
            instance.category, context={"request": request}
        ).data
        return rep

    def create(self, validated_data):
        """
        use custom create to:
        - create new post by the request of authorized user
        """
        validated_data["author"] = Profile.objects.get(
            user__id=self.context.get("request").user.id
        )
        return super().create(validated_data)
