from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.decorators import user_passes_test
from django.http import HttpResponse
from store.models import Product



def listing(request):
    data = {
        "products": Product.objects.all(),
    }
    return render(request, "store/listing.html", data)

def view_product(request, product_id):
    product = get_object_or_404(Product, id=product_id)
    data = {
        "product": product,
    }

    return render(request, "store/view_product.html", data)


def see_request(request):
    text = f"""
        Some attributes of the HttpRequest object:

        scheme: {request.scheme}
        path:   {request.path}
        method: {request.method}
        GET:    {request.GET}
        user:   {request.user}
    """

    return HttpResponse(text, content_type="text/plain")


def user_info(request):
    text = f"""
        Selected HttpRequest.user attributes:

        username:     {request.user.username}
        is_anonymous: {request.user.is_anonymous}
        is_staff:     {request.user.is_staff}
        is_superuser: {request.user.is_superuser}
        is_active:    {request.user.is_active}
    """

    return HttpResponse(text, content_type="text/plain")


@login_required
def private_place(request):
    return HttpResponse("Shhh, members only!", content_type="text/plain")


@user_passes_test(lambda user: user.is_staff)
def staff_place(request):
    return HttpResponse("Employees must wash hands", content_type="text/plain")