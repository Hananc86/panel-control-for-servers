import React from 'react';
import Collapsible from 'react-collapsible';
import groupsData from '../data/groupsData';

class Groups extends React.Component {

    constructor() {
        super();
        this.state = {
            search: '',
        }
    }

    onChange(e) {
        this.setState({
            search: e.target.value,
        })
    }

    render() {
        let groupList = groupsData.filter(
            (group) => {
                if (group.group.toLowerCase().indexOf(this.state.search.toLowerCase()) !== -1 || group.owner_name.toLowerCase().indexOf(this.state.search.toLowerCase()) !== -1) {
                    return group;
                } else {
                    return false;
                }
            }
        );

        groupList = groupList.map((map)=> {
            const serverHeaderData = (
                <div className="rowContainer serversRowContainer">
                    <li className="col-md-6 col-xs-6">{map.group}</li>
                    <li className="col-md-6 col-xs-6">{map.owner_name}</li>
                </div>
            );
            
            const userData = (
                <div className="serverData">
                    <ul>
                        <li>-- {map.id}</li>
                        <li>-- {map.group}</li>
                        <li>-- {map.owner_name}</li>
                    </ul>
                </div>
            );
            return (
                <Collapsible trigger={serverHeaderData} key={map.id}>
                    {userData}
                </Collapsible>
            );
        });
        return (
            <div className="container">
                <h2>Search:</h2>
                <div className="searchBox">
                    <input
                        type="text"
                        className="form-control"
                        onChange={ this.onChange.bind(this) }
                        value={this.state.search}
                    />
                </div>
                <div className="content serverContainer">
                    <div className="rowContainer clearfix">
                        <div className="rowHeader col-md-6 col-xs-6">Group Name</div>
                        <div className="rowHeader col-md-6 col-xs-6">Mange By</div>
                    </div>
                    {groupList}
                </div>
            </div>
        )
    }
}


export default Groups;