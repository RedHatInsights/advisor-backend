# Copyright 2016-2024 the Advisor Backend team at Red Hat.
# This file is part of the Insights Advisor project.

# Insights Advisor is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.

# Insights Advisor is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.

# You should have received a copy of the GNU General Public License along
# with Insights Advisor. If not, see <https://www.gnu.org/licenses/>.

from django.db.models import Count, Q, Value
from django.utils.decorators import method_decorator

from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from drf_spectacular.utils import extend_schema

from api.models import RuleRating
from api.serializers import (
    AllRuleRatingsSerializer, RuleRatingSerializer, RuleRatingStatsSerializer
)
from api.permissions import (
    request_to_username, IsRedHatInternalUser, InsightsRBACPermission,
    set_resource, ResourceScope,
)
from api.utils import (
    CustomPageNumberPagination, PaginateMixin, store_post_data,
)


class RedHatRatingStatsPermission(IsRedHatInternalUser):
    allowed_views = ['Stats', 'All ratings']


@method_decorator(
    name='retrieve',
    decorator=extend_schema(
        summary="Retrieve the ratings for a single rule",
        description="Retrieve the ratings for a single rule, by Insights Rule ID",
    )
)
class RuleRatingViewSet(PaginateMixin, viewsets.ReadOnlyModelViewSet):
    """
    Rules can be rated +1, 0 or -1; the rating is stored per (user, rule)
    unique pair.  Rule ratings are edited simply by POSTing a new rating,
    which overwrites any previous rating by that user for that rule.

    detail: View the user's rating for a specific rule.  If the user has not
    rated this rule, a 404 is returned.
    """
    lookup_field = 'rule__rule_id'
    lookup_url_kwarg = 'rule'
    pagination_class = CustomPageNumberPagination
    permission_classes = [InsightsRBACPermission | RedHatRatingStatsPermission]
    queryset = RuleRating.objects.all()
    resource_name = 'recommendation-results'
    resource_scope = ResourceScope.ORG
    serializer_class = RuleRatingSerializer

    def get_queryset(self):
        """
        Get the rules rated by the current user.
        """
        username = request_to_username(self.request)
        return self.queryset.filter(rated_by=username)

    def list(self, request, format=None):
        """
        List all rules rated by the current user

        Only the current user's ratings are listed here.
        """
        return self._paginated_response(self.get_queryset(), request)

    @extend_schema(
        responses={
            200: RuleRatingSerializer(many=False),
            201: RuleRatingSerializer(many=False),
        }
    )
    def create(self, request, format=None):
        """
        Add or update a rating for a rule, by rule ID.

        Return the new rating.  Any previous rating for this rule by this
        user is amended to the current value.  This does not attempt to delete
        a rating by this user of this rule if the rating is zero.
        """
        username = request_to_username(self.request)
        store_post_data(request, RuleRatingSerializer)
        rating_serdata = RuleRatingSerializer(data=request.data)
        rating_serdata.is_valid(raise_exception=True)
        rating, created = self.get_queryset().update_or_create(
            rated_by=username, rule=rating_serdata.validated_data['rule'],
            defaults={
                'rating': rating_serdata.validated_data['rating'],
                'account': request.account,  # Remove after org_id adoption
                'org_id': request.auth['org_id']
            },
        )
        return Response(RuleRatingSerializer(
            rating, many=False, context={'request': request}
        ).data, status=201 if created else 200)

    @set_resource('denied')
    @extend_schema(
        responses={200: AllRuleRatingsSerializer(many=True)},
    )
    @action(detail=False)
    def all_ratings(self, request, format=None):
        """
        Show all ratings.

        Available only to internal users.
        """
        return self._paginated_response(
            RuleRating.objects.all(), request, serializer_class=AllRuleRatingsSerializer
        )

    @set_resource('denied')
    @extend_schema(
        responses={200: RuleRatingStatsSerializer(many=True)},
    )
    @action(detail=False)
    def stats(self, request, format=None):
        """
        Summarise the ratings for a rule.

        This summarises the statistics for each rule.  Available only to
        internal users.
        """
        counts = RuleRating.objects.values('rule__rule_id').order_by(
            'rule__rule_id'
        ).annotate(
            total_ratings=Count('id', distinct=True),
            total_positive=Count('id', filter=Q(rating=Value(1)), distinct=True),
            total_negative=Count('id', filter=Q(rating=Value(-1)), distinct=True)
        )
        return self._paginated_response(
            counts, request, serializer_class=RuleRatingStatsSerializer
        )
