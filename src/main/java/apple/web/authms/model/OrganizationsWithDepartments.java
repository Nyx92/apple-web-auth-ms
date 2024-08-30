package apple.web.authms.model;

public class OrganizationsWithDepartments {
    private String organization;
    private String department;

    public String getOrganization() {
        return this.organization;
    }

    public String getDepartment() {
        return this.department;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    public void setDepartment(String department) {
        this.department = department;
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        } else if (!(o instanceof OrganizationsWithDepartments)) {
            return false;
        } else {
            OrganizationsWithDepartments other = (OrganizationsWithDepartments)o;
            if (!other.canEqual(this)) {
                return false;
            } else {
                Object this$organization = this.getOrganization();
                Object other$organization = other.getOrganization();
                if (this$organization == null) {
                    if (other$organization != null) {
                        return false;
                    }
                } else if (!this$organization.equals(other$organization)) {
                    return false;
                }

                Object this$department = this.getDepartment();
                Object other$department = other.getDepartment();
                if (this$department == null) {
                    if (other$department != null) {
                        return false;
                    }
                } else if (!this$department.equals(other$department)) {
                    return false;
                }

                return true;
            }
        }
    }

    protected boolean canEqual(Object other) {
        return other instanceof OrganizationsWithDepartments;
    }

    public int hashCode() {
        boolean PRIME = true;
        int result = 1;
        Object $organization = this.getOrganization();
        result = result * 59 + ($organization == null ? 43 : $organization.hashCode());
        Object $department = this.getDepartment();
        result = result * 59 + ($department == null ? 43 : $department.hashCode());
        return result;
    }

    public String toString() {
        String var10000 = this.getOrganization();
        return "OrganizationsWithDepartments(organization=" + var10000 + ", department=" + this.getDepartment() + ")";
    }

    public OrganizationsWithDepartments() {
    }

    public OrganizationsWithDepartments(String organization, String department) {
        this.organization = organization;
        this.department = department;
    }
}