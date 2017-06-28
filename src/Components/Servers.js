import React from 'react';
import Collapsible from 'react-collapsible';
import ServersList from '../actions/serversAction';
import ReactCSSTransitionGroup from 'react-addons-css-transition-group';
import PopUp from './PopUp';
import user from '../user';


class Servers extends React.Component {

    constructor(props) {
        super(props);
        this.state = {
            search: '',
            popUpData: '',
            dates: {
                from: '',
                to: ''
            }
        }
    }

    onChange(e) {
        this.setState({
            search: e.target.value,
        });
    }

    onClick(server) {
        this.setState({
            popUpData: server,
        })
    }


    render() {

        let ServerMapping = ServersList.filter(
            (server) => {
                if (server.Short_name.toLowerCase().indexOf(this.state.search.toLowerCase()) !== -1 || server.Internal_IP.toLowerCase().indexOf(this.state.search.toLowerCase()) !== -1 || server.group_name.toLowerCase().indexOf(this.state.search.toLowerCase()) !== -1) {
                    return server;
                } else {
                    return false;
                }
            }
        );
        ServerMapping = ServerMapping.map((server) => {
            const serverHeaderData = (
                <div className="rowContainer serversRowContainer">
                    <li className="col-md-3 col-xs-3">{server.Internal_IP}</li>
                    <li className="col-md-3 col-xs-3">{server.Short_name}</li>
                    <li className="col-md-3 col-xs-3">{server.Operator}</li>
                    <li className="col-md-3 col-xs-3">{server.group_name}</li>
                </div>
            );

            const serverData = (
                <div className="serverData">
                    <ul>
                        <li className="col-md-4"><b>Name: </b>{server.Short_name}</li>
                        <li className="col-md-4"><b>Host Name:</b> {server.Host_name}</li>
                        <li className="col-md-4"><b>IP: </b>{server.Internal_IP}</li>
                        <li className="col-md-4"><b>Owner: </b>{server.Owner}</li>
                        <li className="col-md-4"><b>App Version:</b> {server.App_Version}</li>
                        <li className="col-md-4"><b>Environment: </b>{server.Environment}</li>
                        <li className="col-md-4"><b>Managed By Cheaf?: </b> {server.Managed_By_chef}</li>
                        <li className="col-md-4"><b>OS: </b>{server.OS_version}</li>
                        { server.group_name === user.group_name || user.is_admin === 1 ?
                            <li>
                                <button type="button" className="btn btn-primary" data-toggle="modal" value={server}
                                        onClick={() => this.onClick(server)} data-target="#gridSystemModal">Set Dates
                                </button>
                            </li>
                            :
                            <li>
                                <button type="button" className="btn btn-primary disabled">Set Dates</button>
                            </li>
                        }

                    </ul>
                </div>
            );
            return (
                <Collapsible trigger={serverHeaderData} key={server.Internal_IP}>
                    {serverData}
                </Collapsible>
            );
        });
        const popUpData = this.state.popUpData;
        return (
            <div className="container">
                <PopUp popUpData={popUpData}/>
                <h2>Search:</h2>
                <div className="searchBox">
                    <input
                        type="text"
                        className="form-control"
                        onChange={ this.onChange.bind(this) }
                        value={this.state.search}
                    />
                </div>
                <div className="content">
                    <div className="serverContainer clearfix">
                        <div className="rowContainer">
                            <div className="serverIp rowHeader col-md-3 col-xs-3">Server IP</div>
                            <div className="serverName rowHeader col-md-3 col-xs-3">Server Name</div>
                            <div className="serverStatus rowHeader col-md-3 col-xs-3">Server Status</div>
                            <div className="serverGroup rowHeader col-md-3 col-xs-3">Group</div>
                        </div>
                    </div>
                    <ReactCSSTransitionGroup
                        transitionName="transition"
                        transitionEnterTimeout={500}
                        transitionLeaveTimeout={300}>
                        {ServerMapping}
                    </ReactCSSTransitionGroup>
                </div>
            </div>
        )
    }
}

export default Servers;