from django import forms
from django.conf import settings
from django.core.exceptions import MultipleObjectsReturned, ObjectDoesNotExist, ValidationError
from django.utils.translation import gettext as _

from extras.models import Tag
from tenancy.models import Tenant
from dcim.models import Device, Site
from ipam.models import IPAddress, Prefix, ASN
from ipam.formfields import IPNetworkFormField
from utilities.forms.fields import (
    DynamicModelChoiceField, CSVModelChoiceField,
    DynamicModelMultipleChoiceField,
    TagFilterField, CSVChoiceField,
    ChoiceField
)
from utilities.forms.widgets import APISelect, APISelectMultiple
from netbox.forms import NetBoxModelForm, NetBoxModelBulkEditForm, NetBoxModelFilterSetForm, NetBoxModelImportForm  

from .models import (
    Community, BGPSession, RoutingPolicy, BGPPeerGroup,
    RoutingPolicyRule, PrefixList, PrefixListRule
)

from .choices import SessionStatusChoices, CommunityStatusChoices, IPAddressFamilyChoices

from dcim.models import Device, VirtualChassis
from virtualization.models import VirtualMachine


class CommunityForm(NetBoxModelForm):
    tags = DynamicModelMultipleChoiceField(
        queryset=Tag.objects.all(),
        required=False
    )
    status = forms.ChoiceField(
        required=False,
        choices=CommunityStatusChoices,
    )
    tenant = DynamicModelChoiceField(
        queryset=Tenant.objects.all(),
        required=False
    )

    class Meta:
        model = Community
        fields = [
            'value', 'description', 'status', 'tenant', 'tags',
        ]


class CommunityFilterForm(NetBoxModelFilterSetForm):
    q = forms.CharField(
        required=False,
        label='Search'
    )
    tenant = DynamicModelChoiceField(
        queryset=Tenant.objects.all(),
        required=False
    )
    status = forms.MultipleChoiceField(
        choices=CommunityStatusChoices,
        required=False,
    )
    site = DynamicModelChoiceField(
        queryset=Site.objects.all(),
        required=False
    )

    tag = TagFilterField(Community)

    model = Community


class CommunityBulkEditForm(NetBoxModelBulkEditForm):
    pk = forms.ModelMultipleChoiceField(
        queryset=Community.objects.all(),
        widget=forms.MultipleHiddenInput
    )
    tenant = DynamicModelChoiceField(
        queryset=Tenant.objects.all(),
        required=False
    )
    description = forms.CharField(
        max_length=200,
        required=False
    )
    status = forms.ChoiceField(
        required=False,
        choices=CommunityStatusChoices,
    )

    model = Community
    nullable_fields = [
       'tenant', 'description',
    ]

class CommunityImportForm(NetBoxModelImportForm):
    tenant = CSVModelChoiceField(
        queryset=Tenant.objects.all(),
        required=False,
        to_field_name='name',
        help_text=_('Assigned tenant')
    )

    status = CSVChoiceField(
        choices=CommunityStatusChoices,
        help_text=_('Operational status')
    )    

    class Meta:
        model = Community
        fields = ('value', 'description', 'tags')    


class BGPSessionForm(NetBoxModelForm):
    name = forms.CharField(
        max_length=64,
        required=True
    )
    tags = DynamicModelMultipleChoiceField(
        queryset=Tag.objects.all(),
        required=False
    )
    site = DynamicModelChoiceField(
        queryset=Site.objects.all(),
        required=False
    )

    # Device selector
    device = DynamicModelChoiceField(
        queryset=Device.objects.all(),
        required=False,
        query_params={
            'site_id': '$site',
        },
        label=_('Device')
    )

    # Virtual Chassis selector
    virtual_chassis = DynamicModelChoiceField(
        queryset=VirtualChassis.objects.all(),
        required=False,
        label=_('Virtual chassis')
    )

    # Virtual Machine selector
    virtual_machine = DynamicModelChoiceField(
        queryset=VirtualMachine.objects.all(),
        required=False,
        query_params={
            'site_id': '$site',
        },
        label=_('Virtual machine')
    )

    tenant = DynamicModelChoiceField(
        queryset=Tenant.objects.all(),
        required=False
    )
    local_as = DynamicModelChoiceField(
        queryset=ASN.objects.all(),
        query_params={
            'site_id': '$site'
        },
        label=_('Local AS')
    )
    remote_as = DynamicModelChoiceField(
        queryset=ASN.objects.all(),
        label=_('Remote AS')
    )
    local_address = DynamicModelChoiceField(
        queryset=IPAddress.objects.all(),
        query_params={
            'device_id': '$device',
            'virtual_machine_id': '$virtual_machine',
        }
    )
    remote_address = DynamicModelChoiceField(
        queryset=IPAddress.objects.all(),
    )
    peer_group = DynamicModelChoiceField(
        queryset=BGPPeerGroup.objects.all(),
        required=False,
        widget=APISelect(
            api_url='/api/plugins/bgp/peer-group/',
        )
    )
    import_policies = DynamicModelMultipleChoiceField(
        queryset=RoutingPolicy.objects.all(),
        required=False,
        widget=APISelectMultiple(
            api_url='/api/plugins/bgp/routing-policy/'
        )
    )
    export_policies = DynamicModelMultipleChoiceField(
        queryset=RoutingPolicy.objects.all(),
        required=False,
        widget=APISelectMultiple(
            api_url='/api/plugins/bgp/routing-policy/'
        )
    )
    import_prefix_lists = DynamicModelMultipleChoiceField(
        queryset=PrefixList.objects.all(),
        required=False,
        widget=APISelectMultiple(
            api_url='/api/plugins/bgp/prefix-list/'
        )
    )
    export_prefix_lists = DynamicModelMultipleChoiceField(
        queryset=PrefixList.objects.all(),
        required=False,
        widget=APISelectMultiple(
            api_url='/api/plugins/bgp/prefix-list/'
        )
    )

    class Meta:
        model = BGPSession
        fields = [
            'name', 'site', 'device', 'virtual_chassis', 'virtual_machine',
            'local_as', 'remote_as', 'local_address', 'remote_address',
            'description', 'status', 'peer_group', 'tenant', 'tags', 'import_policies', 'export_policies',
            'import_prefix_lists', 'export_prefix_lists'
        ]
        fieldsets = (
            ('Session', ('name', 'site', 'device', 'virtual_chassis', 'virtual_machine', 'description', 'status', 'peer_group', 'tenant', 'tags')),
            ('Remote', ('remote_as', 'remote_address')),
            ('Local', ('local_as', 'local_address')),
            ('Policies', ('import_policies', 'export_policies')),
            ('Prefix Lists', ('import_prefix_lists', 'export_prefix_lists')),
        )
        widgets = {
            'status': forms.Select(),
        }

    def __init__(self, *args, **kwargs):
        instance = kwargs.get("instance")
        initial = kwargs.get("initial", {}).copy()
        if instance:
            if isinstance(instance.assigned_object, Device):
                initial["device"] = instance.assigned_object
            elif isinstance(instance.assigned_object, VirtualMachine):
                initial["virtual_machine"] = instance.assigned_object
            elif isinstance(instance.assigned_object, VirtualChassis):
                initial["virtual_chassis"] = instance.assigned_object

        print(initial)

        kwargs["initial"] = initial
        super().__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super().clean()

        device = cleaned_data.get("device")
        virtual_chassis = cleaned_data.get("virtual_chassis")
        virtual_machine = cleaned_data.get("virtual_machine")

        if (device and virtual_chassis) or (device and virtual_machine) or (virtual_chassis and virtual_machine):
            raise forms.ValidationError(
                "BGP Sessions must be assigned to one target at a time. Either a device, virtual chassis or virtual machine."
            )

        # Check if no hosts selected.
        if not device and not virtual_chassis and not virtual_machine:
            raise forms.ValidationError(
                "BGP Sessions must be assigned to a device, virtual chassis or virtual machine.",
            )

        return cleaned_data

    def save(self, *args, **kwargs):
        # Set assigned object
        self.instance.assigned_object = (
                self.cleaned_data.get('device')
                or self.cleaned_data.get('virtual_chassis')
                or self.cleaned_data.get('virtual_machine')
        )

        return super().save(*args, **kwargs)


class BGPSessionAddForm(BGPSessionForm):
    remote_address = IPNetworkFormField()

    def clean_remote_address(self):
        try:
            ip = IPAddress.objects.get(address=str(self.cleaned_data['remote_address']))
        except MultipleObjectsReturned:
            ip = IPAddress.objects.filter(address=str(self.cleaned_data['remote_address'])).first()
        except ObjectDoesNotExist:
            ip = IPAddress.objects.create(address=str(self.cleaned_data['remote_address']))
        self.cleaned_data['remote_address'] = ip
        return self.cleaned_data['remote_address']


class BGPSessionFilterForm(NetBoxModelFilterSetForm):
    model = BGPSession
    q = forms.CharField(
        required=False,
        label='Search'
    )
    remote_as_id = DynamicModelMultipleChoiceField(
        queryset=ASN.objects.all(),
        required=False,
        label=_('Remote AS')
    )
    local_as_id = DynamicModelMultipleChoiceField(
        queryset=ASN.objects.all(),
        required=False,
        label=_('Local AS')
    )
    by_local_address = forms.CharField(
        required=False,
        label='Local Address'
    )
    by_remote_address = forms.CharField(
        required=False,
        label='Remote Address'
    )
    device_id = DynamicModelMultipleChoiceField(
        queryset=Device.objects.all(),
        required=False,
        label=_('Device')
    )
    status = forms.MultipleChoiceField(
        choices=SessionStatusChoices,
        required=False,
    )
    peer_group = DynamicModelMultipleChoiceField(
        queryset=BGPPeerGroup.objects.all(),
        required=False,
        widget=APISelectMultiple(
            api_url='/api/plugins/bgp/peer-group/'
        )
    )
    import_policies = DynamicModelMultipleChoiceField(
        queryset=RoutingPolicy.objects.all(),
        required=False,
        widget=APISelectMultiple(
            api_url='/api/plugins/bgp/routing-policy/'
        )
    )
    export_policies = DynamicModelMultipleChoiceField(
        queryset=RoutingPolicy.objects.all(),
        required=False,
        widget=APISelectMultiple(
            api_url='/api/plugins/bgp/routing-policy/'
        )
    )
    import_prefix_lists = DynamicModelMultipleChoiceField(
        queryset=PrefixList.objects.all(),
        required=False,
        widget=APISelectMultiple(
            api_url='/api/plugins/bgp/prefix-list/'
        )
    )
    export_prefix_lists = DynamicModelMultipleChoiceField(
        queryset=PrefixList.objects.all(),
        required=False,
        widget=APISelectMultiple(
            api_url='/api/plugins/bgp/prefix-list/'
        )
    )
    tenant = DynamicModelChoiceField(
        queryset=Tenant.objects.all(),
        required=False
    )

    tag = TagFilterField(model)


class RoutingPolicyFilterForm(NetBoxModelFilterSetForm):
    model = RoutingPolicy
    q = forms.CharField(
        required=False,
        label='Search'
    )

    tag = TagFilterField(model)


class RoutingPolicyForm(NetBoxModelForm):
    tags = DynamicModelMultipleChoiceField(
        queryset=Tag.objects.all(),
        required=False
    )

    class Meta:
        model = RoutingPolicy
        fields = ['name', 'description', 'tags']


class BGPPeerGroupFilterForm(NetBoxModelFilterSetForm):
    model = BGPPeerGroup
    q = forms.CharField(
        required=False,
        label='Search'
    )

    tag = TagFilterField(model)


class BGPPeerGroupForm(NetBoxModelForm):
    import_policies = DynamicModelMultipleChoiceField(
        queryset=RoutingPolicy.objects.all(),
        required=False,
        widget=APISelectMultiple(
            api_url='/api/plugins/bgp/routing-policy/'
        )
    )
    export_policies = DynamicModelMultipleChoiceField(
        queryset=RoutingPolicy.objects.all(),
        required=False,
        widget=APISelectMultiple(
            api_url='/api/plugins/bgp/routing-policy/'
        )
    )
    import_prefix_lists = DynamicModelMultipleChoiceField(
        queryset=PrefixList.objects.all(),
        required=False,
        widget=APISelectMultiple(
            api_url='/api/plugins/bgp/prefix-list/'
        )
    )
    export_prefix_lists = DynamicModelMultipleChoiceField(
        queryset=PrefixList.objects.all(),
        required=False,
        widget=APISelectMultiple(
            api_url='/api/plugins/bgp/prefix-list/'
        )
    )
    tags = DynamicModelMultipleChoiceField(
        queryset=Tag.objects.all(),
        required=False
    )

    class Meta:
        model = BGPPeerGroup
        fields = [
            'name', 'description', 'import_policies', 'export_policies',
            'import_prefix_lists', 'export_prefix_lists', 'tags'
        ]


class RoutingPolicyRuleForm(NetBoxModelForm):
    continue_entry = forms.IntegerField(
        required=False,
        label='Continue',
        help_text='Null for disable, 0 to next entry, or any sequence number'
    )
    match_community = DynamicModelMultipleChoiceField(
        queryset=Community.objects.all(),
        required=False,
    )
    match_ip_address = DynamicModelMultipleChoiceField(
        queryset=PrefixList.objects.all(),
        required=False,
        label='Match IP address Prefix lists',
    )
    match_ipv6_address = DynamicModelMultipleChoiceField(
        queryset=PrefixList.objects.all(),
        required=False,
        label='Match IPv6 address Prefix lists',
    )
    match_custom = forms.JSONField(
        label='Custom Match',
        help_text='Any custom match statements, e.g., {"ip nexthop": "1.1.1.1"}',
        required=False,
    )
    set_actions = forms.JSONField(
        label='Set statements',
        help_text='Set statements, e.g., {"as-path prepend": [12345,12345]}',
        required=False
    )

    class Meta:
        model = RoutingPolicyRule
        fields = [
            'routing_policy', 'index', 'action', 'continue_entry', 'match_community',
            'match_ip_address', 'match_ipv6_address', 'match_custom',
            'set_actions', 'description',
        ]


class PrefixListFilterForm(NetBoxModelFilterSetForm):
    model = PrefixList
    q = forms.CharField(
        required=False,
        label='Search'
    )

    tag = TagFilterField(model)


class PrefixListForm(NetBoxModelForm):
    tags = DynamicModelMultipleChoiceField(
        queryset=Tag.objects.all(),
        required=False
    )
    family = ChoiceField(
        required=True,
        choices=IPAddressFamilyChoices,
    )

    class Meta:
        model = PrefixList
        fields = ['name', 'description', 'family', 'tags']


class PrefixListRuleForm(NetBoxModelForm):
    prefix = DynamicModelChoiceField(
        queryset=Prefix.objects.all(),
        required=False,
        help_text='NetBox Prefix Object',
    )
    prefix_custom = IPNetworkFormField(
        required=False,
        label='Prefix',
        help_text='Just IP field for define special prefix like 0.0.0.0/0',
    )
    ge = forms.IntegerField(
        label='Greater than or equal to',
        required=False,
    )
    le = forms.IntegerField(
        label='Less than or equal to',
        required=False,
    )

    class Meta:
        model = PrefixListRule
        fields = [
            'prefix_list', 'index',
            'action', 'prefix', 'prefix_custom',
            'ge', 'le'
        ]
