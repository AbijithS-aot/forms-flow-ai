import React /*{useEffect}*/ from "react";
import { NavDropdown } from "react-bootstrap";
import { useDispatch, useSelector } from "react-redux";
import {
  setSelectedBPMFilter,
  setSelectedTaskID,
} from "../../../actions/bpmTaskActions";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { MULTITENANCY_ENABLED } from "../../../constants/constants";
// import { fetchBPMTaskDetail } from "../../../apiManager/services/bpmTaskServices";

const ServiceFlowFilterListDropDown = React.memo(({selectFilter,openFilterDrawer}) => {
  const dispatch = useDispatch();
  const filterList = useSelector((state) => state.bpmTasks.filterList);
  const isFilterLoading = useSelector(
    (state) => state.bpmTasks.isFilterLoading
  );
  // const bpmFiltersList = useSelector(
  //   (state) => state.bpmTasks.filterList
  // );
  const selectedFilter = useSelector((state) => state.bpmTasks.selectedFilter);
  const { t } = useTranslation();
  const tenantKey = useSelector((state) => state.tenants?.tenantId);
  const redirectUrl = MULTITENANCY_ENABLED ? `/tenant/${tenantKey}/` : "/";

  const changeFilterSelection = (filter) => {
    // const selectedBPMFilterId = bpmFiltersList.find(item => item.id === filter.id);
    // fetchBPMTaskDetail(selectedBPMFilterId).then((res)=>{
    //   dispatch(setBPMTaskList(res.data));
    // }).catch((err)=>{
    //   console.error(err);
    // }).finally(()=>{
    //   dispatch(setBPMTaskLoader(false));
    // });
    dispatch(setSelectedBPMFilter(filter));
    dispatch(setSelectedTaskID(null));
  };

  const handleFilterEdit = (id) => {
    selectFilter(filterList.find((item) => item.id === id));
  };

  const renderFilterList = () => {
    if (filterList.length) {
      return (
        <>
          {filterList.map((filter, index) => (
            <NavDropdown.Item
              as={Link}
              to={`${redirectUrl}task`}
              className={`main-nav nav-item ${
                filter?.id === selectedFilter?.id ? "active-tab" : ""
              }`}
              key={index}
            >
              <div className="icon-and-text">
                <span onClick={() => changeFilterSelection(filter)}>
                  {filter?.name} {`(${filter.count || 0})`}
                </span>
                <i
                  className="fa fa-pencil ml-5"
                  onClick={() => {
                    handleFilterEdit(filter?.id);
                    openFilterDrawer(true);
                  }}
                />
              </div>
            </NavDropdown.Item>
          ))}
        </>
      );
    } else {
      return (
        <NavDropdown.Item className="not-selected mt-2 ml-1">
          <i className="fa fa-info-circle mr-2 mt-1" />
          {t("No Filters Found")}
        </NavDropdown.Item>
      );
    }
  };
  return (
    <>
      {isFilterLoading ? (
        <NavDropdown.Item>{t("Loading")}...</NavDropdown.Item>
      ) : (
        renderFilterList()
      )}
    </>
  );
});

export default ServiceFlowFilterListDropDown;
