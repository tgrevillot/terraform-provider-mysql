package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDefaultRoles() *schema.Resource {
	return &schema.Resource{
		CreateContext: CreateDefaultRoles,
		UpdateContext: UpdateDefaultRoles,
		ReadContext:   ReadDefaultRoles,
		DeleteContext: DeleteDefaultRoles,
		Importer: &schema.ResourceImporter{
			StateContext: ImportDefaultRoles,
		},

		Schema: map[string]*schema.Schema{
			"user": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},

			"host": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Default:  "localhost",
			},

			"roles": {
				Type:     schema.TypeSet,
				Required: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Set: schema.HashString,
			},

			"use_set_role_statement": {
				Type:	  schema.TypeBool,
				Optional: true,
				Default:  false
			},
		},
	}
}

func checkDefaultRolesSupport(ctx context.Context, meta interface{}) error {
	ver, _ := version.NewVersion("8.0.0")
	if getVersionFromMeta(ctx, meta).LessThan(ver) {
		return errors.New("MySQL version must be at least 8.0.0")
	}
	return nil
}

func alterUserDefaultRoles(ctx context.Context, db *sql.DB, user, host string, roles []string, preferred_set_default_role_statement bool) error {
	var stmtSQL []string

	if preferred_set_default_role_statement {
		if(len(roles) > 0) {
			//REVIEW: Iterating here on roles but only one can be set with mariaDB. Useful for MySQL thought. 
			for(i = 0; i < len(roles); i++) {
				stmtSQL = append(stmtSQL, fmt.Sprintf("SET DEFAULT ROLE %s FOR USER '%s'@'%s'", roles[i], user, host))
			}
		} else {
			stmtSQL = append(fmt.Sprintf("SET DEFAULT ROLE NONE FOR USER '%s'@'%s'", user, host)
		}
	} else {
		stmtSQL = append(stmtSQL, fmt.Sprintf("ALTER USER '%s'@'%s' DEFAULT ROLE ", user, host))
		if len(roles) > 0 {
			stmtSQL[0] += fmt.Sprintf("'%s'", strings.Join(roles, "', '"))
		} else {
			stmtSQL[0] += "NONE"
		}
	}

	for i = 0; i < len(stmtSQL); i++) {
		log.Println("[DEBUG] Executing statement:", stmtSQL[i])
		_, err := db.ExecContext(ctx, stmtSQL[i])
		if err != nil {
			return fmt.Errorf("failed executing SQL: %w", err)
		}
	}

	return nil
}

func getRolesFromData(d *schema.ResourceData) []string {
	defaultRoles := d.Get("roles").(*schema.Set).List()
	roles := make([]string, len(defaultRoles))
	for i, role := range defaultRoles {
		roles[i] = role.(string)
	}

	return roles
}

func CreateDefaultRoles(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	db, err := getDatabaseFromMeta(ctx, meta)
	if err != nil {
		return diag.FromErr(err)
	}
	if err := checkDefaultRolesSupport(ctx, meta); err != nil {
		return diag.Errorf("cannot use default roles: %v", err)
	}

	user := d.Get("user").(string)
	host := d.Get("host").(string)
	roles := getRolesFromData(d)
	preferred_statement := d.Get("use_set_role_statement").(bool)

	if err := alterUserDefaultRoles(ctx, db, user, host, roles, preferred_statement); err != nil {
		return diag.Errorf("failed to create user default roles: %v", err)
	}

	d.SetId(fmt.Sprintf("%s@%s", user, host))

	return nil
}

func UpdateDefaultRoles(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	db, err := getDatabaseFromMeta(ctx, meta)
	if err != nil {
		return diag.FromErr(err)
	}
	if err := checkDefaultRolesSupport(ctx, meta); err != nil {
		return diag.Errorf("cannot use default roles: %v", err)
	}

	if d.HasChange("roles") {
		user := d.Get("user").(string)
		host := d.Get("host").(string)
		roles := getRolesFromData(d)
		preferred_statement := d.Get("use_set_role_statement").(bool)

		if err := alterUserDefaultRoles(ctx, db, user, host, roles, preferred_statement); err != nil {
			return diag.Errorf("failed to update user default roles: %v", err)
		}
	}

	return nil
}

func ReadDefaultRoles(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	db, err := getDatabaseFromMeta(ctx, meta)
	if err != nil {
		return diag.FromErr(err)
	}
	if err := checkDefaultRolesSupport(ctx, meta); err != nil {
		return diag.Errorf("cannot use default roles: %v", err)
	}

	stmtSQL := "SELECT default_role_user FROM mysql.default_roles WHERE user = ? AND host = ?"

	log.Println("[DEBUG] Executing statement:", stmtSQL)

	rows, err := db.QueryContext(ctx, stmtSQL, d.Get("user").(string), d.Get("host").(string))
	if err != nil {
		return diag.Errorf("failed to read user default roles from DB: %v", err)
	}
	defer rows.Close()

	var defaultRoles = make([]string, 0)
	for rows.Next() {
		var role string
		err := rows.Scan(&role)
		if err != nil {
			return diag.Errorf("failed scanning default roles: %v", err)
		}
		defaultRoles = append(defaultRoles, role)
	}

	if rows.Err() != nil {
		return diag.Errorf("failed getting rows: %v", rows.Err())
	}

	d.Set("roles", defaultRoles)

	return nil
}

func DeleteDefaultRoles(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	db, err := getDatabaseFromMeta(ctx, meta)
	if err != nil {
		return diag.FromErr(err)
	}
	if err := checkDefaultRolesSupport(ctx, meta); err != nil {
		return diag.Errorf("cannot use default roles: %v", err)
	}

	user := d.Get("user").(string)
	host := d.Get("host").(string)
	preferred_statement := d.Get("use_set_role_statement").(bool)

	if err := alterUserDefaultRoles(ctx, db, user, host, []string{}, preferred_statement); err != nil {
		return diag.Errorf("failed to remove user default roles: %v", err)
	}

	d.SetId("")

	return nil
}

func ImportDefaultRoles(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	userHost := strings.SplitN(d.Id(), "@", 2)

	if len(userHost) != 2 {
		return nil, fmt.Errorf("wrong ID format %s (expected USER@HOST)", d.Id())
	}

	d.Set("user", userHost[0])
	d.Set("host", userHost[1])

	readDiags := ReadDefaultRoles(ctx, d, meta)
	for _, readDiag := range readDiags {
		if readDiag.Severity == diag.Error {
			return nil, fmt.Errorf("failed to read default roles: %s", readDiag.Summary)
		}
	}

	return []*schema.ResourceData{d}, nil
}
