import { STAFF_REVIEWER, STAFF_DESIGNER } from "../constants/constants";
const getUserRoleName = (userRoles) => {
  let role = "";
  if (userRoles.includes(STAFF_REVIEWER)) {
    role = "REVIEWER";
  } else if (userRoles.includes(STAFF_DESIGNER)) {
    role = "DESIGNER";
  } else {
    role = "CLIENT";
  }
  return role;
};

const getUserRolePermission = (userRoles, role) => {
  return userRoles && userRoles.includes(role);
};

export { getUserRoleName, getUserRolePermission };
