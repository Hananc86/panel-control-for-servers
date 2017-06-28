import React from 'react';
import $ from 'jquery';
import user from '../user';
import Datepicker from './Datepicker';

export default class PopUp extends React.Component {

    constructor() {
        super();
        this.state = {
            dates: '',
        }
    }

    saveChanges() {

        if (this.props.popUpData.group_name !== user.group_name) {
            return alert("You can't access to this server!!!!");
        } else if ($('#from').val() === '' || $('#to').val() === '') {
            alert("Can't save change of empty string");
        } else {
            this.setState({
                dates: {
                    from: $('#from').val(),
                    to: $('#to').val()
                }
            });
        }
    }


    render() {
        return (
            <div className="modal fade" id="gridSystemModal" tabIndex="-1" role="dialog"
                 aria-labelledby="gridSystemModalLabel">
                <div className="modal-dialog" role="document">
                    <div className="modal-content">
                        <div className="modal-header">
                            <button type="button" className="close" data-dismiss="modal" aria-label="Close"><span
                                aria-hidden="true">&times;</span></button>
                            <h4 className="modal-title" id="gridSystemModalLabel">Set dates
                                for {this.props.popUpData.Short_name}</h4>
                        </div>
                        <div className="modal-body">
                            <h4>Server Name: {this.props.popUpData.Short_name}</h4>
                            <h4>Server IP: {this.props.popUpData.Internal_IP}</h4>
                            <h4>Owner: {this.props.popUpData.Owner}</h4>
                        </div>
                        <Datepicker />
                        <div className="modal-footer">
                            <button type="button" className="btn btn-default" data-dismiss="modal">Close</button>
                            <button type="button" className="btn btn-primary btnSaveCahnges"
                                    onClick={this.saveChanges.bind(this)}>Save changes
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        )
    }
}