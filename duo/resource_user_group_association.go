package duo

import (
	"encoding/json"
	"fmt"
	"net/url"

	duoapi "github.com/duosecurity/duo_api_golang"
	admin "github.com/duosecurity/duo_api_golang/admin"
	"github.com/hashicorp/terraform/helper/schema"
)

func resourceUserGroupAssociation() *schema.Resource {
	return &schema.Resource{
		Create: resourceUserGroupAssociationCreate,
		Read:   resourceUserGroupAssociationRead,
		Delete: resourceUserGroupAssociationDelete,

		Schema: map[string]*schema.Schema{
			"user_id": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"group_id": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
		},
	}
}

type AssociationResult struct {
	duoapi.StatResult
}

func resourceUserGroupAssociationCreate(d *schema.ResourceData, meta interface{}) error {
	duoclient := meta.(*duoapi.DuoApi)
	duoAdminClient := admin.New(*duoclient)

	gid := d.Get("group_id").(string)
	uid := d.Get("user_id").(string)

	params := url.Values{}

	params.Set("group_id", gid)

	_, body, err := duoAdminClient.SignedCall("POST", fmt.Sprintf("/admin/v1/users/%s/groups", uid), params, duoapi.UseTimeout)
	if err != nil {
		return err
	}

	result := &AssociationResult{}
	err = json.Unmarshal(body, result)
	if err != nil {
		return err
	}
	if result.Stat != "OK" {
		return fmt.Errorf("could not associate group to user %s %s", result.Stat, *result.Message)
	}
	d.SetId(fmt.Sprintf("%s-%s", d.Get("user_id").(string), d.Get("group_id").(string)))
	return resourceUserGroupAssociationRead(d, meta)
}

func resourceUserGroupAssociationRead(d *schema.ResourceData, meta interface{}) error {
	duoclient := meta.(*duoapi.DuoApi)
	duoAdminClient := admin.New(*duoclient)
	gid := d.Get("group_id").(string)
	uid := d.Get("user_id").(string)
	result, err := duoAdminClient.GetGroup(gid)
	if err != nil {
		return err
	}
	if result.Stat != "OK" {
		return fmt.Errorf(fmt.Sprintf("could not find group %s", gid))
	}

	var found bool
	var foundUser string
	for _, v := range result.Response.Users {
		if v.UserID == d.Get("user_id").(string) {
			found = true
			foundUser = v.UserID
		}
	}
	if !found {
		return fmt.Errorf("could not find group %s attached to user %s", gid, uid)
	}
	d.Set("group_id", gid)
	d.Set("user_id", foundUser)
	return nil
}

func resourceUserGroupAssociationDelete(d *schema.ResourceData, meta interface{}) error {
	duoclient := meta.(*duoapi.DuoApi)
	duoAdminClient := admin.New(*duoclient)

	gid := d.Get("group_id").(string)
	uid := d.Get("user_id").(string)
	_, body, err := duoAdminClient.SignedCall("DELETE", fmt.Sprintf("/admin/v1/users/%s/groups/%s", uid, gid), nil, duoapi.UseTimeout)
	if err != nil {
		return err
	}

	result := &AssociationResult{}
	err = json.Unmarshal(body, result)
	if err != nil {
		return err
	}
	if result.Stat != "OK" {
		return fmt.Errorf("could not disassociate group %s from user %s: %+v", gid, uid, *result.Message)
	}
	return nil
}
