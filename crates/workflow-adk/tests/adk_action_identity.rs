use adk_rust::adk_action::ActionNodeConfig;
use adk_rust::graph::action::ActionNodeExecutor;

#[test]
fn umbrella_action_config_is_accepted_by_the_graph_executor() {
    let _constructor: fn(ActionNodeConfig) -> ActionNodeExecutor = ActionNodeExecutor::new;
}
