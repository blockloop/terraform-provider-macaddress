package macaddress

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

const MAC_ADDRESS_LENGTH = 6

func resourceAddress() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceAddressCreate,
		Read:          schema.Noop,
		Delete:        schema.RemoveFromState,
		Schema: map[string]*schema.Schema{
			"address": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"prefix": {
				Type: schema.TypeList,
				Elem: &schema.Schema{
					Type: schema.TypeInt,
				},
				Optional: true,
				ForceNew: true,
			},
		},
		Importer: &schema.ResourceImporter{
			State: resourceAddressImport,
		},
	}
}

func resourceAddressImport(d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	address := d.Id()
	parts := strings.Split(address, ":")
	if len(parts) != 6 {
		return nil, fmt.Errorf("%s is not a valid mac address", address)
	}
	for _, p := range parts {
		_, err := strconv.ParseInt(p, 16, 16)
		if err != nil {
			return nil, fmt.Errorf("%s is not a valid mac address", address)
		}
	}
	d.Set("address", address)
	return []*schema.ResourceData{d}, nil
}

func SeedFromString(s string) int64 {
	h := md5.New()
	_, _ = io.WriteString(h, s)
	var seed uint64 = (binary.BigEndian.Uint64(h.Sum(nil)))
	return int64(seed)
}

func Create(seed string, prefix []interface{}) (string, error) {
	var groups []string
	buf := make([]byte, MAC_ADDRESS_LENGTH)

	if seed != "" {
		rand.Seed(SeedFromString(seed))
	}

	_, err := rand.Read(buf) //nolint
	if err != nil {
		return "", err
	}

	// Locally administered
	buf[0] |= 0x02

	// Unicast
	buf[0] &= 0xfe

	if len(prefix) > MAC_ADDRESS_LENGTH {
		return "", errors.New("error generating random mac address: prefix is too large")
	}

	for index, val := range prefix {
		if val.(int) > 255 {
			return "", errors.New("error generating random mac address: prefix segment must be in the range [0,256)")
		}
		buf[index] = byte(val.(int))
	}

	for _, i := range buf {
		groups = append(groups, fmt.Sprintf("%02x", i))
	}

	address := strings.Join(groups, ":")

	return address, nil
}

func resourceAddressCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	seedStr := d.Get("seed").(string)
	prefix := d.Get("prefix").([]interface{})

	address, err := Create(seedStr, prefix)
	if err != nil {
		return diag.FromErr(errors.New("error generating random mac address: prefix segment must be in the range [0,256)"))
	}

	d.SetId(address)
	d.Set("address", address)

	return nil
}
