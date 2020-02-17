// Code generated by go-swagger; DO NOT EDIT.

package ipam

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"

	strfmt "github.com/go-openapi/strfmt"
)

// NewDeleteIPAMIPParams creates a new DeleteIPAMIPParams object
// with the default values initialized.
func NewDeleteIPAMIPParams() *DeleteIPAMIPParams {
	var ()
	return &DeleteIPAMIPParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewDeleteIPAMIPParamsWithTimeout creates a new DeleteIPAMIPParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewDeleteIPAMIPParamsWithTimeout(timeout time.Duration) *DeleteIPAMIPParams {
	var ()
	return &DeleteIPAMIPParams{

		timeout: timeout,
	}
}

// NewDeleteIPAMIPParamsWithContext creates a new DeleteIPAMIPParams object
// with the default values initialized, and the ability to set a context for a request
func NewDeleteIPAMIPParamsWithContext(ctx context.Context) *DeleteIPAMIPParams {
	var ()
	return &DeleteIPAMIPParams{

		Context: ctx,
	}
}

// NewDeleteIPAMIPParamsWithHTTPClient creates a new DeleteIPAMIPParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewDeleteIPAMIPParamsWithHTTPClient(client *http.Client) *DeleteIPAMIPParams {
	var ()
	return &DeleteIPAMIPParams{
		HTTPClient: client,
	}
}

/*DeleteIPAMIPParams contains all the parameters to send to the API endpoint
for the delete IP a m IP operation typically these are written to a http.Request
*/
type DeleteIPAMIPParams struct {

	/*IP
	  IP address or owner name

	*/
	IP string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the delete IP a m IP params
func (o *DeleteIPAMIPParams) WithTimeout(timeout time.Duration) *DeleteIPAMIPParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the delete IP a m IP params
func (o *DeleteIPAMIPParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the delete IP a m IP params
func (o *DeleteIPAMIPParams) WithContext(ctx context.Context) *DeleteIPAMIPParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the delete IP a m IP params
func (o *DeleteIPAMIPParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the delete IP a m IP params
func (o *DeleteIPAMIPParams) WithHTTPClient(client *http.Client) *DeleteIPAMIPParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the delete IP a m IP params
func (o *DeleteIPAMIPParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIP adds the ip to the delete IP a m IP params
func (o *DeleteIPAMIPParams) WithIP(ip string) *DeleteIPAMIPParams {
	o.SetIP(ip)
	return o
}

// SetIP adds the ip to the delete IP a m IP params
func (o *DeleteIPAMIPParams) SetIP(ip string) {
	o.IP = ip
}

// WriteToRequest writes these params to a swagger request
func (o *DeleteIPAMIPParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param ip
	if err := r.SetPathParam("ip", o.IP); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
