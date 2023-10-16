import React, { useCallback, useEffect, useRef } from "react";
import ServiceFlowTaskList from "./list/ServiceTaskList";
import ServiceTaskListView from "./list/ServiceTaskListView";
import ServiceTaskListViewDetails from './list/ServiceTaskListViewDetails';


import ServiceFlowTaskDetails from "./details/ServiceTaskDetails";
import { Col, Container, Row } from "react-bootstrap";
import "./ServiceFlow.scss";
import {
  fetchBPMTaskCount,
  fetchFilterList,
  fetchProcessDefinitionList,
  fetchServiceTaskList,
  getBPMGroups,
  getBPMTaskDetail,
} from "../../apiManager/services/bpmTaskServices";
import { useDispatch, useSelector } from "react-redux";
import { ALL_TASKS } from "./constants/taskConstants";
import {
  reloadTaskFormSubmission,
  setBPMFilterLoader,
  setBPMFiltersAndCount,
  setBPMTaskDetailLoader,
  setFilterListParams,
  setSelectedBPMFilter,
  setSelectedTaskID,
} from "../../actions/bpmTaskActions";
import TaskSortSelectedList from "./list/sort/TaskSortSelectedList";
import SocketIOService from "../../services/SocketIOService";
import isEqual from "lodash/isEqual";
import cloneDeep from "lodash/cloneDeep";
import { Route, Redirect, Switch } from "react-router-dom";
import { push, replace } from "connected-react-router";
import { BASE_ROUTE,MULTITENANCY_ENABLED } from "../../constants/constants";
import TaskHead from "../../containers/TaskHead";

export default React.memo(() => {
  const dispatch = useDispatch();
  const filterList = useSelector((state) => state.bpmTasks.filterList);
  const selectedFilterId = useSelector(
    (state) => state.bpmTasks.selectedFilter?.id || null
  );
  const bpmFiltersList = useSelector(
    (state) => state.bpmTasks.filterList
  );
  const bpmTaskId = useSelector((state) => state.bpmTasks.taskId);
  const reqData = useSelector((state) => state.bpmTasks.listReqParams);
  const sortParams = useSelector(
    (state) => state.bpmTasks.filterListSortParams
  );
  const searchParams = useSelector(
    (state) => state.bpmTasks.filterListSearchParams
  );
  const listReqParams = useSelector((state) => state.bpmTasks.listReqParams);
  const currentUser = useSelector(
    (state) => state.user?.userDetail?.preferred_username || ""
  );
  const filterListAndCount = useSelector(
    (state) => state.bpmTasks.filtersAndCount
  );
  const firstResult = useSelector((state) => state.bpmTasks.firstResult);
  const taskList = useSelector((state) => state.bpmTasks.tasksList);
  const selectedFilterIdRef = useRef(selectedFilterId);
  const bpmTaskIdRef = useRef(bpmTaskId);
  const reqDataRef = useRef(reqData);
  const firstResultsRef = useRef(firstResult);
  const taskListRef = useRef(taskList);
  const tenantKey = useSelector((state) => state.tenants?.tenantId);
  const cardView = useSelector(
    (state) => state.bpmTasks.viewType
  );
  
  const redirectUrl = useRef(
    MULTITENANCY_ENABLED ? `/tenant/${tenantKey}/` : "/"
  );

  let selectedBPMFilterParams;

  useEffect(() => {
    selectedFilterIdRef.current = selectedFilterId;
    bpmTaskIdRef.current = bpmTaskId;
    reqDataRef.current = reqData;
    firstResultsRef.current = firstResult;
    taskListRef.current = taskList;
    redirectUrl.current = MULTITENANCY_ENABLED ? `/tenant/${tenantKey}/` : "/";
  });

  useEffect(() => {
    const reqParamData = {
      ...{ sorting: [...sortParams.sorting] },
      ...searchParams,
    };
    selectedBPMFilterParams = bpmFiltersList.find(
      (item) => item.id === selectedFilterId
    );
    if(selectedBPMFilterParams){
      selectedBPMFilterParams = {
        ...selectedBPMFilterParams,
        criteria: {
          ...selectedBPMFilterParams?.criteria,
          ...reqParamData
        }
      };
    }
    if (!isEqual(selectedBPMFilterParams, listReqParams) && selectedBPMFilterParams) {
      dispatch(setFilterListParams(cloneDeep(selectedBPMFilterParams)));
    }
  }, [selectedFilterId]);

  useEffect(() => {
    console.log("inside useeffectt 22");
    const reqParamData = {
      ...{ sorting: [...sortParams.sorting] },
      ...searchParams,
    };
    selectedBPMFilterParams = bpmFiltersList.find(
      (item) => item.id === selectedFilterId
    );
    if(selectedBPMFilterParams){
      selectedBPMFilterParams = {
        ...selectedBPMFilterParams,
        criteria: {
          ...selectedBPMFilterParams?.criteria,
          ...reqParamData
        }
      };
    }
    if (!isEqual(selectedBPMFilterParams, listReqParams) && selectedBPMFilterParams) {
      dispatch(setFilterListParams(cloneDeep(selectedBPMFilterParams)));
    }
  }, [searchParams, sortParams, dispatch, listReqParams]);


  useEffect(() => {
    dispatch(setBPMFilterLoader(true));
    dispatch(fetchFilterList((err,data)=>{
      if(data){
        fetchBPMTaskCount(data).then((res)=>{
          dispatch(setBPMFiltersAndCount(res.data));
        }).catch((err)=>{
          if(err){
            console.error(err);
          }
        }).finally(()=>{
          dispatch(setBPMFilterLoader(false));
        });
      }
    }));
    dispatch(fetchProcessDefinitionList());
  }, [dispatch]);

  useEffect(()=>{
    if(filterListAndCount?.length){
      let filterSelected;
      if (filterList.length > 1) {
        filterSelected = filterListAndCount?.find((filter) => filter.name === ALL_TASKS);
        if (!filterSelected) {
          filterSelected = filterListAndCount[0];
        }
      } else {
        filterSelected = filterListAndCount[0];
      }
      dispatch(setSelectedBPMFilter(filterSelected));
    }
  },[filterListAndCount?.length]);

  const checkIfTaskIDExistsInList = (list, id) => {
    return list.some((task) => task.id === id);
  };
  const SocketIOCallback = useCallback(
    (refreshedTaskId, forceReload, isUpdateEvent) => {
      if (forceReload) {
        console.log("calling 1");
        dispatch(
          fetchServiceTaskList(
            selectedBPMFilterParams,
            refreshedTaskId
          )
        ); //Refreshes the Tasks
        if (bpmTaskIdRef.current && refreshedTaskId === bpmTaskIdRef.current) {
          dispatch(setBPMTaskDetailLoader(true));
          dispatch(setSelectedTaskID(null)); // unSelect the Task Selected
          dispatch(push(`${redirectUrl.current}task/`));
        }
      } else {
        if (selectedFilterIdRef.current) {
          if (isUpdateEvent) {
            /* Check if the taskId exists in the loaded Task List */
            if (
              checkIfTaskIDExistsInList(
                taskListRef.current,
                refreshedTaskId
              ) === true
            ) {
              console.log("calling 2");
              dispatch(
                fetchServiceTaskList(
                  selectedBPMFilterParams
                )
              ); //Refreshes the Task
            }
          } else {
            console.log("calling 3");
            dispatch(
              fetchServiceTaskList(
                selectedBPMFilterParams
              )
            ); //Refreshes the Task
          }
        }
        if (bpmTaskIdRef.current && refreshedTaskId === bpmTaskIdRef.current) {
          //Refreshes task if its selected
          dispatch(
            getBPMTaskDetail(bpmTaskIdRef.current, (err, resTask) => {
              // Should dispatch When task claimed user  is not the logged in User
              if (resTask?.assignee !== currentUser) {
                dispatch(reloadTaskFormSubmission(true));
              }
            })
          );
          dispatch(getBPMGroups(bpmTaskIdRef.current));
        }
      }
    },
    [dispatch, currentUser]
  );

  useEffect(() => {
    if (!SocketIOService.isConnected()) {
      SocketIOService.connect((refreshedTaskId, forceReload, isUpdateEvent) =>
        SocketIOCallback(refreshedTaskId, forceReload, isUpdateEvent)
      );
    } else {
      SocketIOService.disconnect();
      SocketIOService.connect((refreshedTaskId, forceReload, isUpdateEvent) =>
        SocketIOCallback(refreshedTaskId, forceReload, isUpdateEvent)
      );
    }
    return () => {
      if (SocketIOService.isConnected()) SocketIOService.disconnect();
    };
  }, [SocketIOCallback, dispatch]);
  //Reset the path when the 'cardView' changes
  useEffect(() => {
    dispatch(replace(`${BASE_ROUTE}task`));
  }, [cardView, dispatch]);

  return (
    <Container fluid id="main" className="pt-0">
      {cardView ? (
        <>
        <TaskHead />
        <Row className="p-2">
        <Col lg={3} xs={12} sm={12} md={4} xl={3}>
          <section>
            <header className="task-section-top">
              <TaskSortSelectedList />
            </header>
            <ServiceFlowTaskList />
          </section>
        </Col>
        <Col className="pl-0" lg={9} xs={12} sm={12} md={8} xl={9}>
          <Switch>
            <Route
              path={`${BASE_ROUTE}task/:taskId?`}
              component={ServiceFlowTaskDetails}
            ></Route>
            <Route path={`${BASE_ROUTE}task/:taskId/:notAvailable`}>
              {" "}
              <Redirect exact to="/404" />
            </Route>
          </Switch>
        </Col>
        </Row>
        </>
      ) :
        (
          <Switch>
            <Route
              exact
              path={`${BASE_ROUTE}task`}
              render={() => (
                <>
                  <TaskHead />
                  <ServiceTaskListView />
                </>
              )}
            >
            </Route>
            <Route
              path={`${BASE_ROUTE}task/:taskId`}
              render={() => (
                <>
                  
                  <ServiceTaskListViewDetails />
                </>
              )}
              
            ></Route>
            <Route path={`${BASE_ROUTE}task/:taskId/:notAvailable`}>
              <Redirect exact to="/404" />
            </Route>
          </Switch>
        ) }
    </Container>
  );
});
